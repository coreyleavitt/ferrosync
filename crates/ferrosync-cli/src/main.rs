use clap::Parser;

#[derive(Parser)]
#[command(name = "ferrosync", version, about = "rsync wire protocol implementation")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Push files to a remote destination
    Push {
        /// Source path
        source: String,
        /// Destination path (local or remote)
        dest: String,
    },
    /// Pull files from a remote source
    Pull {
        /// Source path (local or remote)
        source: String,
        /// Destination path
        dest: String,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Push { source, dest }) => {
            eprintln!("push {source} -> {dest} (not yet implemented)");
        }
        Some(Commands::Pull { source, dest }) => {
            eprintln!("pull {source} -> {dest} (not yet implemented)");
        }
        None => {
            eprintln!("ferrosync: no command specified. Use --help for usage.");
        }
    }
}
