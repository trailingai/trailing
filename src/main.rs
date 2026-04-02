use clap::Parser;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = trailing::cli::Cli::parse();
    trailing::cli::run(cli).await
}
