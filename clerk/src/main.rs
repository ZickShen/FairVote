
#[macro_use]
extern crate serde_derive;
use std::collections::HashMap;
#[macro_use] extern crate prettytable;
use prettytable::{Table};

#[derive(Debug, Serialize, Deserialize)]
pub struct Candidates {
    candidates: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
    let mut stat = HashMap::new();
    let mut statistics = Table::new();
    let table = reqwest::get("http://192.168.16.128:8080/")
        .await?
        .text()
        .await?;
    let table = table_extract::Table::find_first(&table).unwrap();
    for row in &table {
        let vote = row.get("m").unwrap_or("<vote missing>");
        let vote: Candidates = serde_json::from_str(vote).unwrap();
        for candidate in vote.candidates {
            let entry = stat.entry(candidate).or_insert(0);
            *entry += 1;
        }
    }
    statistics.add_row(row!["candidate", "amount"]);
    for (candidate, amount) in stat {
        statistics.add_row(row![candidate, amount]);
    }
    statistics.printstd();
    Ok(())
}
