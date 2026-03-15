use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use clap::{Args, Parser, Subcommand};
use reqwest::{Client, Method, StatusCode};
use secret_engine_core::model::{
    SecretListResponse, SecretMetadataResponse, SecretReadResponse, SecretVersionActionRequest,
    SecretWriteRequest, SecretWriteResponse, SystemInitResponse, SystemInitStatusResponse,
    SystemKeyReencryptRequest, SystemKeyReencryptResponse, SystemKeyRotateResponse,
    SystemKeyStatusResponse, SystemRootRecoverRequest, SystemRootRecoverResponse,
    SystemRootRotateResponse, TokenCreateRequest, TokenCreateResponse, TokenListResponse,
    TokenScope,
};
use url::Url;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    name = "secretsctl",
    version,
    about = "Vault-like CLI for secret-engine"
)]
struct Cli {
    #[arg(
        long,
        env = "SECRET_ENGINE_ADDR",
        default_value = "http://127.0.0.1:8080"
    )]
    addr: String,
    #[arg(long, env = "SECRET_ENGINE_TOKEN")]
    token: Option<String>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Login(LoginArgs),
    Status,
    Sys {
        #[command(subcommand)]
        command: SysCommand,
    },
    Kv {
        #[command(subcommand)]
        command: KvCommand,
    },
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
}

#[derive(Debug, Subcommand)]
enum SysCommand {
    Init,
    Status,
    Keys {
        #[command(subcommand)]
        command: SysKeyCommand,
    },
    Root {
        #[command(subcommand)]
        command: SysRootCommand,
    },
}

#[derive(Debug, Subcommand)]
enum SysKeyCommand {
    Status,
    Rotate,
    Reencrypt(SysKeyReencryptArgs),
}

#[derive(Debug, Subcommand)]
enum SysRootCommand {
    Rotate,
    Revoke,
    Recover(SysRecoverArgs),
}

#[derive(Debug, Args)]
struct SysRecoverArgs {
    #[arg(long)]
    recovery_key: String,
}

#[derive(Debug, Args)]
struct SysKeyReencryptArgs {
    #[arg(long, default_value_t = 100)]
    batch_size: i64,
}

#[derive(Debug, Args)]
struct LoginArgs {
    #[arg(long)]
    token: String,
}

#[derive(Debug, Subcommand)]
enum KvCommand {
    Put(KvPutArgs),
    Get(KvGetArgs),
    Metadata(KvPathArgs),
    Undelete(KvVersionActionArgs),
    Destroy(KvVersionActionArgs),
    Delete(KvPathArgs),
    List(KvListArgs),
}

#[derive(Debug, Subcommand)]
enum TokenCommand {
    List,
    Create(TokenCreateArgs),
    Delete(TokenDeleteArgs),
}

#[derive(Debug, Args)]
struct KvPutArgs {
    #[arg(long, default_value = "kv")]
    mount: String,
    path: String,
    value: String,
}

#[derive(Debug, Args)]
struct KvPathArgs {
    #[arg(long, default_value = "kv")]
    mount: String,
    path: String,
}

#[derive(Debug, Args)]
struct KvGetArgs {
    #[arg(long, default_value = "kv")]
    mount: String,
    #[arg(long)]
    version: Option<i32>,
    path: String,
}

#[derive(Debug, Args)]
struct KvListArgs {
    #[arg(long, default_value = "kv")]
    mount: String,
    #[arg(long)]
    prefix: Option<String>,
}

#[derive(Debug, Args)]
struct KvVersionActionArgs {
    #[arg(long, default_value = "kv")]
    mount: String,
    #[arg(long = "version", required = true)]
    versions: Vec<i32>,
    path: String,
}

#[derive(Debug, Args)]
struct TokenCreateArgs {
    #[arg(long)]
    label: String,
    #[arg(long, default_value_t = false)]
    admin: bool,
    #[arg(long)]
    expires_at: Option<String>,
    #[arg(long = "policy")]
    policies: Vec<String>,
}

#[derive(Debug, Args)]
struct TokenDeleteArgs {
    token_id: Uuid,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let api = Api::new(&cli.addr, cli.token.clone())?;

    match cli.command {
        Commands::Login(args) => {
            println!("export SECRET_ENGINE_TOKEN={}", args.token);
        }
        Commands::Status => api.status().await?,
        Commands::Sys { command } => match command {
            SysCommand::Init => api.sys_init().await?,
            SysCommand::Status => api.sys_status().await?,
            SysCommand::Keys { command } => match command {
                SysKeyCommand::Status => api.sys_keys_status().await?,
                SysKeyCommand::Rotate => api.sys_keys_rotate().await?,
                SysKeyCommand::Reencrypt(args) => api.sys_keys_reencrypt(args).await?,
            },
            SysCommand::Root { command } => match command {
                SysRootCommand::Rotate => api.sys_root_rotate().await?,
                SysRootCommand::Revoke => api.sys_root_revoke().await?,
                SysRootCommand::Recover(args) => api.sys_root_recover(args).await?,
            },
        },
        Commands::Kv { command } => match command {
            KvCommand::Put(args) => api.kv_put(args).await?,
            KvCommand::Get(args) => api.kv_get(args).await?,
            KvCommand::Metadata(args) => api.kv_metadata(args).await?,
            KvCommand::Undelete(args) => api.kv_undelete(args).await?,
            KvCommand::Destroy(args) => api.kv_destroy(args).await?,
            KvCommand::Delete(args) => api.kv_delete(args).await?,
            KvCommand::List(args) => api.kv_list(args).await?,
        },
        Commands::Token { command } => match command {
            TokenCommand::List => api.token_list().await?,
            TokenCommand::Create(args) => api.token_create(args).await?,
            TokenCommand::Delete(args) => api.token_delete(args).await?,
        },
    }

    Ok(())
}

struct Api {
    base_url: Url,
    token: Option<String>,
    client: Client,
}

impl Api {
    fn new(base: &str, token: Option<String>) -> Result<Self> {
        Ok(Self {
            base_url: Url::parse(base).context("invalid SECRET_ENGINE_ADDR")?,
            token,
            client: Client::new(),
        })
    }

    async fn status(&self) -> Result<()> {
        let response = self.client.get(self.url("/health")?).send().await?;
        if response.status() != StatusCode::OK {
            bail!("server status check failed: {}", response.status());
        }
        println!("server ok");
        Ok(())
    }

    async fn sys_init(&self) -> Result<()> {
        let response: SystemInitResponse = self
            .send::<()>(Method::POST, "/api/v1/sys/init", None)
            .await?
            .json()
            .await?;

        println!("system initialized at {}", response.initialized_at);
        println!("root token: {}", response.root_token);
        println!("recovery key: {}", response.recovery_key);
        println!("export SECRET_ENGINE_TOKEN={}", response.root_token);
        Ok(())
    }

    async fn sys_status(&self) -> Result<()> {
        let response: SystemInitStatusResponse = self
            .send::<()>(Method::GET, "/api/v1/sys/init", None)
            .await?
            .json()
            .await?;

        if let Some(initialized_at) = response.initialized_at {
            println!("initialized=true at {initialized_at}");
        } else {
            println!("initialized=false");
        }
        Ok(())
    }

    async fn sys_root_rotate(&self) -> Result<()> {
        let response: SystemRootRotateResponse = self
            .send::<()>(Method::POST, "/api/v1/sys/root/rotate", None)
            .await?
            .json()
            .await?;

        println!("root rotated at {}", response.rotated_at);
        println!("new root token: {}", response.root_token);
        println!("new recovery key: {}", response.recovery_key);
        println!("export SECRET_ENGINE_TOKEN={}", response.root_token);
        Ok(())
    }

    async fn sys_root_revoke(&self) -> Result<()> {
        let response = self
            .send::<()>(Method::POST, "/api/v1/sys/root/revoke", None)
            .await?;
        if response.status() != StatusCode::NO_CONTENT {
            bail!("root revoke failed: {}", response.status());
        }
        println!("root token revoked");
        Ok(())
    }

    async fn sys_root_recover(&self, args: SysRecoverArgs) -> Result<()> {
        let payload = SystemRootRecoverRequest {
            recovery_key: args.recovery_key,
        };
        let response: SystemRootRecoverResponse = self
            .send(Method::POST, "/api/v1/sys/root/recover", Some(&payload))
            .await?
            .json()
            .await?;

        println!("root recovered at {}", response.recovered_at);
        println!("new root token: {}", response.root_token);
        println!("new recovery key: {}", response.recovery_key);
        println!("export SECRET_ENGINE_TOKEN={}", response.root_token);
        Ok(())
    }

    async fn sys_keys_status(&self) -> Result<()> {
        let response: SystemKeyStatusResponse = self
            .send::<()>(Method::GET, "/api/v1/sys/keys", None)
            .await?
            .json()
            .await?;

        println!("active key: {}", response.active_key_id);
        println!("stale ciphertext rows: {}", response.stale_ciphertext_count);
        for key in response.keys {
            let state = if key.deactivated_at.is_some() {
                "inactive"
            } else {
                "active"
            };
            println!(
                "{} {} created_at={} activated_at={}",
                key.key_id, state, key.created_at, key.activated_at
            );
        }
        Ok(())
    }

    async fn sys_keys_rotate(&self) -> Result<()> {
        let response: SystemKeyRotateResponse = self
            .send::<()>(Method::POST, "/api/v1/sys/keys/rotate", None)
            .await?
            .json()
            .await?;

        println!("active key rotated to {}", response.active_key.key_id);
        println!("activated at {}", response.active_key.activated_at);
        Ok(())
    }

    async fn sys_keys_reencrypt(&self, args: SysKeyReencryptArgs) -> Result<()> {
        let payload = SystemKeyReencryptRequest {
            batch_size: args.batch_size,
        };
        let response: SystemKeyReencryptResponse = self
            .send(Method::POST, "/api/v1/sys/keys/reencrypt", Some(&payload))
            .await?
            .json()
            .await?;

        println!(
            "reencrypted {} rows to {} ({} remaining)",
            response.reencrypted_count, response.active_key_id, response.remaining_count
        );
        Ok(())
    }

    async fn token_list(&self) -> Result<()> {
        let response: TokenListResponse = self
            .send::<()>(Method::GET, "/api/v1/tokens", None)
            .await?
            .json()
            .await?;

        for item in response.items {
            println!(
                "{} {} admin={} expires_at={}",
                item.id,
                item.label,
                item.admin,
                item.expires_at
                    .map(|value| value.to_rfc3339())
                    .unwrap_or_else(|| "none".to_string())
            );
            for scope in item.scopes {
                println!(
                    "  policy mount={} path_prefix={} capabilities={}",
                    scope.mount,
                    scope.path_prefix,
                    scope.capabilities.join(",")
                );
            }
        }

        Ok(())
    }

    async fn token_create(&self, args: TokenCreateArgs) -> Result<()> {
        let expires_at = parse_optional_datetime(args.expires_at.as_deref())?;
        let scopes = parse_policies(&args.policies)?;
        let payload = TokenCreateRequest {
            label: args.label,
            admin: args.admin,
            expires_at,
            scopes,
        };

        let response: TokenCreateResponse = self
            .send(Method::POST, "/api/v1/tokens", Some(&payload))
            .await?
            .json()
            .await?;

        println!("token: {}", response.token);
        println!("token id: {}", response.metadata.id);
        println!("label: {}", response.metadata.label);
        println!("admin: {}", response.metadata.admin);
        Ok(())
    }

    async fn token_delete(&self, args: TokenDeleteArgs) -> Result<()> {
        let path = format!("/api/v1/tokens/{}", args.token_id);
        let response = self.send::<()>(Method::DELETE, &path, None).await?;
        if response.status() != StatusCode::NO_CONTENT {
            bail!("token delete failed: {}", response.status());
        }
        println!("deleted token {}", args.token_id);
        Ok(())
    }

    async fn kv_put(&self, args: KvPutArgs) -> Result<()> {
        let payload = SecretWriteRequest { value: args.value };
        let path = format!("/api/v1/kv/{}/{}", args.mount, args.path);
        let response: SecretWriteResponse = self
            .send(Method::POST, &path, Some(&payload))
            .await?
            .json()
            .await?;

        println!(
            "stored {}/{}/{} (version {}, key {})",
            response.mount, response.path, response.key, response.version, response.key_id
        );
        Ok(())
    }

    async fn kv_get(&self, args: KvGetArgs) -> Result<()> {
        let mut url = self.url(&format!("/api/v1/kv/{}/{}", args.mount, args.path))?;
        if let Some(version) = args.version {
            url.query_pairs_mut()
                .append_pair("version", &version.to_string());
        }

        let response: SecretReadResponse = self
            .send_url::<()>(Method::GET, url, None)
            .await?
            .json()
            .await?;

        println!("{}", response.value);
        if response.version != response.current_version {
            println!(
                "read version {} (current version {})",
                response.version, response.current_version
            );
        }
        Ok(())
    }

    async fn kv_metadata(&self, args: KvPathArgs) -> Result<()> {
        let path = format!("/api/v1/kv/{}/metadata/{}", args.mount, args.path);
        let response: SecretMetadataResponse = self
            .send::<()>(Method::GET, &path, None)
            .await?
            .json()
            .await?;

        println!(
            "{}/{}/{} latest={} current={}",
            response.mount,
            response.path,
            response.key,
            response.latest_version,
            response
                .current_version
                .map(|version| version.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        for version in response.versions {
            let state = if version.deleted_at.is_some() {
                "deleted"
            } else {
                "active"
            };
            println!("v{} {}", version.version, state);
        }
        Ok(())
    }

    async fn kv_delete(&self, args: KvPathArgs) -> Result<()> {
        let path = format!("/api/v1/kv/{}/{}", args.mount, args.path);
        let response = self.send::<()>(Method::DELETE, &path, None).await?;
        if response.status() != StatusCode::NO_CONTENT {
            bail!("delete failed: {}", response.status());
        }
        println!("deleted {}", args.path);
        Ok(())
    }

    async fn kv_undelete(&self, args: KvVersionActionArgs) -> Result<()> {
        let path = format!("/api/v1/kv/{}/undelete/{}", args.mount, args.path);
        let payload = SecretVersionActionRequest {
            versions: args.versions,
        };
        let response = self.send(Method::POST, &path, Some(&payload)).await?;
        if response.status() != StatusCode::NO_CONTENT {
            bail!("undelete failed: {}", response.status());
        }
        println!("undeleted {}", args.path);
        Ok(())
    }

    async fn kv_destroy(&self, args: KvVersionActionArgs) -> Result<()> {
        let path = format!("/api/v1/kv/{}/destroy/{}", args.mount, args.path);
        let payload = SecretVersionActionRequest {
            versions: args.versions,
        };
        let response = self.send(Method::POST, &path, Some(&payload)).await?;
        if response.status() != StatusCode::NO_CONTENT {
            bail!("destroy failed: {}", response.status());
        }
        println!("destroyed {}", args.path);
        Ok(())
    }

    async fn kv_list(&self, args: KvListArgs) -> Result<()> {
        let url = self.kv_list_url(&args)?;
        let response: SecretListResponse = self
            .send_url::<()>(Method::GET, url, None)
            .await?
            .json()
            .await?;

        for item in response.items {
            println!("{}/{} (v{})", item.path, item.key, item.version);
        }
        Ok(())
    }

    async fn send<T>(
        &self,
        method: Method,
        path: &str,
        body: Option<&T>,
    ) -> Result<reqwest::Response>
    where
        T: serde::Serialize + ?Sized,
    {
        self.send_url(method, self.url(path)?, body).await
    }

    async fn send_url<T>(
        &self,
        method: Method,
        url: Url,
        body: Option<&T>,
    ) -> Result<reqwest::Response>
    where
        T: serde::Serialize + ?Sized,
    {
        let mut request = self.client.request(method, url);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.json(body);
        }

        let response = request.send().await?;
        if response.status().is_success() {
            return Ok(response);
        }

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!("request failed ({status}): {body}");
    }

    fn url(&self, path: &str) -> Result<Url> {
        self.base_url.join(path).context("failed to build url")
    }

    fn kv_list_url(&self, args: &KvListArgs) -> Result<Url> {
        let mut url = self.url(&format!("/api/v1/kv/{}", args.mount))?;
        if let Some(prefix) = &args.prefix {
            url.query_pairs_mut().append_pair("prefix", prefix);
        }
        Ok(url)
    }
}

fn parse_optional_datetime(raw: Option<&str>) -> Result<Option<DateTime<Utc>>> {
    match raw {
        Some(value) => {
            let parsed = DateTime::parse_from_rfc3339(value)
                .with_context(|| format!("invalid --expires-at value: {value}"))?;
            Ok(Some(parsed.with_timezone(&Utc)))
        }
        None => Ok(None),
    }
}

fn parse_policies(values: &[String]) -> Result<Vec<TokenScope>> {
    let mut scopes = Vec::with_capacity(values.len());
    for value in values {
        let parts: Vec<&str> = value.splitn(3, ':').collect();
        if parts.len() != 3 {
            bail!("invalid --policy format: {value} (expected mount:path_prefix:cap1,cap2)");
        }

        let mount = parts[0].trim();
        if mount.is_empty() {
            bail!("policy mount cannot be empty");
        }

        let path_prefix = parts[1].trim().trim_matches('/').to_string();
        let capabilities = parts[2]
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>();

        scopes.push(TokenScope {
            mount: mount.to_string(),
            path_prefix,
            capabilities,
        });
    }

    Ok(scopes)
}
