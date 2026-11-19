use crate::token::TunnelToken;
use anyhow::{Context, Result};
use capnp::message::ReaderOptions;
use capnp_rpc::rpc_twoparty_capnp::Side;
use capnp_rpc::{twoparty::VatNetwork, Disconnector, RpcSystem};

use crate::tunnelrpc_capnp as schema;

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub uuid: Vec<u8>,
    pub location: String,
    pub remotely_managed: bool,
}

pub struct Registration {
    client: schema::registration_server::Client,
    disconnector: Disconnector<Side>,
    task: tokio::task::JoinHandle<std::result::Result<(), capnp::Error>>,
}

impl Registration {
    /// 在控制流上初始化 Cap'n Proto RPC 并调用 registerConnection。
    /// 必须在 tokio LocalSet 内运行（capnp-rpc 的 RpcSystem 不是 Send）。
    ///
    /// 读写两半做成泛型，使注册逻辑既可用于 QUIC 双向流（futures I/O），
    /// 也可用于 HTTP/2 控制流（tokio I/O 经 compat 转成 futures I/O）。
    pub async fn register<R, W>(
        reader: R,
        writer: W,
        token: &TunnelToken,
        secret: &[u8],
        conn_index: u8,
    ) -> Result<(Self, ConnectionInfo)>
    where
        R: futures::AsyncRead + Unpin + 'static,
        W: futures::AsyncWrite + Unpin + 'static,
    {
        let reader = futures::io::BufReader::new(reader);
        let writer = futures::io::BufWriter::new(writer);
        let network = Box::new(VatNetwork::new(
            reader,
            writer,
            Side::Client,
            ReaderOptions::new(),
        ));
        let mut rpc_system = RpcSystem::new(network, None);
        let disconnector = rpc_system.get_disconnector();
        // vat_id = Side::Server 表示取远端的 bootstrap capability。
        let client: schema::registration_server::Client = rpc_system.bootstrap(Side::Server);
        let task = tokio::task::spawn_local(rpc_system);

        let mut registration = Self {
            client,
            disconnector,
            task,
        };

        let info = registration
            .register_connection(token, secret, conn_index)
            .await?;
        Ok((registration, info))
    }

    async fn register_connection(
        &mut self,
        token: &TunnelToken,
        secret: &[u8],
        conn_index: u8,
    ) -> Result<ConnectionInfo> {
        let mut request = self.client.register_connection_request();
        {
            let mut params = request.get();
            let mut auth = params.reborrow().init_auth();
            auth.set_account_tag(&token.account_tag);
            auth.set_tunnel_secret(secret);
            params.set_tunnel_id(&token.tunnel_id.as_bytes()[..]);
            params.set_conn_index(conn_index);

            let mut options = params.reborrow().init_options();
            let mut client_info = options.reborrow().init_client();
            client_info.set_client_id(&uuid::Uuid::new_v4().as_bytes()[..]);
            // 精简版不声明 datagram / post-quantum，避免 edge 推送我们不处理的能力。
            let features = client_info.reborrow().init_features(0);
            let _ = features;
            client_info.set_version("argo-rs/0.1.0");
            client_info.set_arch(std::env::consts::ARCH);
            options.set_replace_existing(false);
            options.set_compression_quality(0);
            options.set_num_previous_attempts(0);
        }

        let response = request
            .send()
            .promise
            .await
            .context("registerConnection RPC 调用失败")?;
        // 三层：response.get()? -> register_results::Reader
        //   .get_result()? -> connection_response::Reader
        //   .get_result()  -> connection_response::result::Reader（union）
        let result = response.get()?.get_result()?.get_result();
        match result.which()? {
            schema::connection_response::result::WhichReader::Error(err) => {
                let err = err?;
                let cause = err.get_cause()?.to_string()?;
                anyhow::bail!(
                    "edge 拒绝注册: {} (should_retry={})",
                    cause,
                    err.get_should_retry()
                );
            }
            schema::connection_response::result::WhichReader::ConnectionDetails(details) => {
                let details = details?;
                Ok(ConnectionInfo {
                    uuid: details.get_uuid()?.to_vec(),
                    location: details.get_location_name()?.to_string()?,
                    remotely_managed: details.get_tunnel_is_remotely_managed(),
                })
            }
        }
    }

    pub async fn unregister(&self) -> Result<()> {
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.client.unregister_connection_request().send().promise,
        )
        .await
        .context("unregisterConnection RPC 超时")?;
        match resp {
            Ok(_) => Ok(()),
            Err(e) if e.kind == capnp::ErrorKind::Disconnected => {
                // QUIC：edge 收到 unregister 后立即断开控制流、不回正常 response，
                // capnp 报 Disconnected，实际意味着注销已被接受。
                tracing::info!("注销请求已送达，edge 随即断开连接");
                Ok(())
            }
            Err(e)
                if e.kind == capnp::ErrorKind::Failed
                    && e.to_string().to_ascii_lowercase().contains("stream closed") =>
            {
                // HTTP/2：控制流是 H2 stream，edge 接受注销后关闭它，
                // 经 h2io 适配层表现为 "stream closed because of a broken pipe"。
                // 与 QUIC 的 Disconnected 等价，视为注销成功。
                tracing::info!("注销请求已送达，edge 随即关闭 H2 控制流");
                Ok(())
            }
            Err(e) => Err(anyhow::Error::new(e).context("unregisterConnection RPC 调用失败")),
        }
    }

    pub async fn shutdown(self) -> Result<()> {
        // 先让 RPC 运行时处理断连消息，再中止后台任务。
        self.disconnector
            .await
            .context("关闭 Cap'n Proto RPC 连接失败")?;
        self.task.abort();
        Ok(())
    }
}
