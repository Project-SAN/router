#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]

struct Args {
    #[arg(short, long, default_value="ch1")]
    mode: String,
}

fn run_chapter1() {
    Println!("Running chapter 1");
}

fn run_chapter2(mode: &str) {
    Println!("Running chapter 2 with mode: {}", mode);
}

fn main() {
    let args = Args::parse();

    if args.mode == "ch1" {
        run_chapter1();
    } else {
        run_chapter2(&args.mode);
    }
}
