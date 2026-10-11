//! `gnomehome-api` binary: run with `just serve`.

use std::process::ExitCode;

use gnomehome_api::{app, bind_address_from_file, config_path};

#[tokio::main]
async fn main() -> ExitCode {
    let path = config_path();
    let addr = match bind_address_from_file(&path) {
        Ok(addr) => addr,
        Err(err) => {
            eprintln!("gnomehome-api: {err}");
            return ExitCode::FAILURE;
        }
    };

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("gnomehome-api: cannot listen on {addr}: {err}");
            return ExitCode::FAILURE;
        }
    };

    println!("gnomehome-api listening on http://{addr} (Ctrl+C to stop)");
    let shutdown = async {
        // If the signal handler can't be installed, run until killed.
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    if let Err(err) = axum::serve(listener, app())
        .with_graceful_shutdown(shutdown)
        .await
    {
        eprintln!("gnomehome-api: server error: {err}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
