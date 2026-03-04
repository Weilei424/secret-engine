use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use reqwest::{Client, Method, StatusCode};
use secret_engine_core::model::{
    SecretListResponse, SecretReadResponse, SecretWriteRequest, SecretWriteResponse,
};
use url::Url;

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
    Kv {
        #[command(subcommand)]
        command: KvCommand,
    },
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
    Delete(KvPathArgs),
    List(KvListArgs),
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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let api = Api::new(&cli.addr, cli.token.clone())?;

    match cli.command {
        Commands::Login(args) => {
            println!("export SECRET_ENGINE_TOKEN={}", args.token);
        }
        Commands::Status => api.status().await?,
        Commands::Kv { command } => match command {
            KvCommand::Put(args) => api.kv_put(args).await?,
            KvCommand::Get(args) => api.kv_get(args).await?,
            KvCommand::Delete(args) => api.kv_delete(args).await?,
            KvCommand::List(args) => api.kv_list(args).await?,
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

    async fn kv_put(&self, args: KvPutArgs) -> Result<()> {
        let payload = SecretWriteRequest { value: args.value };
        let path = format!("/api/v1/kv/{}/{}", args.mount, args.path);
        let response: SecretWriteResponse = self
            .send(Method::POST, &path, Some(&payload))
            .await?
            .json()
            .await?;

        println!(
            "stored {}/{}/{} (version {})",
            response.mount, response.path, response.key, response.version
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

    async fn kv_delete(&self, args: KvPathArgs) -> Result<()> {
        let path = format!("/api/v1/kv/{}/{}", args.mount, args.path);
        let response = self.send::<()>(Method::DELETE, &path, None).await?;
        if response.status() != StatusCode::NO_CONTENT {
            bail!("delete failed: {}", response.status());
        }
        println!("deleted {}", args.path);
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
