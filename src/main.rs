use clap::Parser;
use std::{collections::BTreeMap, fmt, fs, net::IpAddr, path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(
    version,
    about = "Summarise saved English-language Windows route traces"
)]
struct Arguments {
    #[arg(value_name = "FILE", help = "Windows tracert report to summarise")]
    input: PathBuf,
    #[arg(
        long,
        value_name = "FILE",
        help = "Compare router addresses against an earlier report"
    )]
    compare: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Probe {
    Milliseconds(u64),
    LessThan(u64),
    Unanswered,
}

impl fmt::Display for Probe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Milliseconds(value) => write!(formatter, "{value} ms"),
            Self::LessThan(value) => write!(formatter, "<{value} ms"),
            Self::Unanswered => write!(formatter, "*"),
        }
    }
}

#[derive(Debug)]
struct Hop {
    probes: [Probe; 3],
    address: Option<IpAddr>,
    hostname: Option<String>,
}

#[derive(Debug)]
struct Trace {
    hops: BTreeMap<u32, Hop>,
    destination: Option<IpAddr>,
    complete: bool,
}

fn diagnostic(line: usize, message: impl fmt::Display) -> String {
    format!("line {line}: {message}")
}

fn number(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn parse_probe(fields: &[&str], cursor: &mut usize) -> Result<Probe, String> {
    let token = fields.get(*cursor).ok_or("missing probe field")?;
    *cursor += 1;
    if *token == "*" {
        return Ok(Probe::Unanswered);
    }
    let (less_than, value) = if let Some(bound) = token.strip_prefix('<') {
        let bound = if bound.is_empty() {
            let next = fields
                .get(*cursor)
                .ok_or("missing less-than timing bound")?;
            *cursor += 1;
            *next
        } else {
            bound
        };
        (true, bound)
    } else {
        (false, *token)
    };
    let value = number(value).ok_or_else(|| format!("invalid probe timing '{token}'"))?;
    if fields.get(*cursor) != Some(&"ms") {
        return Err("expected 'ms' after probe timing".into());
    }
    *cursor += 1;
    Ok(if less_than {
        Probe::LessThan(value)
    } else {
        Probe::Milliseconds(value)
    })
}

fn bracketed_address(value: &str) -> Option<IpAddr> {
    value.strip_prefix('[')?.strip_suffix(']')?.parse().ok()
}

fn parse_endpoint(fields: &[&str]) -> Result<(Option<IpAddr>, Option<String>), String> {
    match fields {
        [] | ["Request", "timed", "out."] => Ok((None, None)),
        [endpoint] => {
            if let Ok(address) = endpoint.parse::<IpAddr>() {
                Ok((Some(address), None))
            } else if let Some(address) = bracketed_address(endpoint) {
                Ok((Some(address), None))
            } else if endpoint.contains(['[', ']'])
                || endpoint.parse::<u64>().is_ok()
                || *endpoint == "*"
            {
                Err(format!("invalid hop address '{endpoint}'"))
            } else {
                Ok((None, Some((*endpoint).into())))
            }
        }
        [hostname, endpoint] => {
            let address = bracketed_address(endpoint)
                .ok_or_else(|| format!("invalid hop address '{endpoint}'"))?;
            Ok((Some(address), Some((*hostname).into())))
        }
        _ => Err("unexpected fields after the three probes".into()),
    }
}

fn parse_trace(contents: &str) -> Result<Trace, String> {
    let mut trace = Trace {
        hops: BTreeMap::new(),
        destination: None,
        complete: false,
    };
    let mut line_count = 0;
    let mut reading_destination = false;
    for (index, raw) in contents.lines().enumerate() {
        let line_number = index + 1;
        line_count = line_number;
        let line = raw.trim_start_matches('\u{feff}').trim();
        if line.starts_with("Tracing route to ") {
            reading_destination = true;
        }
        if reading_destination && !line.as_bytes().first().is_some_and(u8::is_ascii_digit) {
            for field in line.split_whitespace() {
                if let Some(address) =
                    bracketed_address(field).or_else(|| field.parse::<IpAddr>().ok())
                {
                    trace.destination = Some(address);
                }
            }
        }
        if line.starts_with("over a maximum of ") {
            reading_destination = false;
            continue;
        }
        if line == "Trace complete." {
            trace.complete = true;
            reading_destination = false;
            continue;
        }
        if !line.as_bytes().first().is_some_and(u8::is_ascii_digit) {
            continue;
        }
        reading_destination = false;
        let fields: Vec<_> = line.split_whitespace().collect();
        let hop_number = number(fields[0])
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value > 0)
            .ok_or_else(|| diagnostic(line_number, "invalid hop number"))?;
        if trace.hops.contains_key(&hop_number) {
            return Err(diagnostic(
                line_number,
                format!("duplicate hop number {hop_number}"),
            ));
        }
        let expected = trace.hops.len() + 1;
        if u64::from(hop_number) != expected as u64 {
            return Err(diagnostic(
                line_number,
                format!("missing hop row {expected}; found hop {hop_number}"),
            ));
        }
        let mut cursor = 1;
        let mut probes = [Probe::Unanswered; 3];
        for (index, probe) in probes.iter_mut().enumerate() {
            *probe = parse_probe(&fields, &mut cursor).map_err(|error| {
                diagnostic(line_number, format!("probe {}: {error}", index + 1))
            })?;
        }
        let (address, hostname) =
            parse_endpoint(&fields[cursor..]).map_err(|error| diagnostic(line_number, error))?;
        trace.hops.insert(
            hop_number,
            Hop {
                probes,
                address,
                hostname,
            },
        );
    }
    if trace.hops.is_empty() {
        return Err(diagnostic(line_count.max(1), "missing hop rows"));
    }
    Ok(trace)
}

fn read_trace(path: &PathBuf) -> Result<Trace, String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("{}: cannot read report: {error}", path.display()))?;
    parse_trace(&contents).map_err(|error| format!("{}: {error}", path.display()))
}

fn print_trace(trace: &Trace) {
    println!("Hop     Probe 1     Probe 2     Probe 3  Router");
    let mut answered = 0;
    for (position, hop) in &trace.hops {
        let probes = hop.probes.map(|probe| probe.to_string());
        let router = match (&hop.hostname, hop.address) {
            (Some(hostname), Some(address)) => format!("{hostname} [{address}]"),
            (None, Some(address)) => address.to_string(),
            (Some(hostname), None) => hostname.clone(),
            (None, None) => "unknown".into(),
        };
        println!(
            "{position:>3}  {:>10}  {:>10}  {:>10}  {router}",
            probes[0], probes[1], probes[2]
        );
        answered += hop
            .probes
            .iter()
            .filter(|probe| **probe != Probe::Unanswered)
            .count();
    }
    println!(
        "Hops: {} | Answered probes: {answered} | Unanswered probes: {}",
        trace.hops.len(),
        trace.hops.len() * 3 - answered
    );
    println!(
        "Trace completion marker: {}",
        if trace.complete { "present" } else { "absent" }
    );
    if let Some(destination) = trace.destination {
        if let Some((position, _)) = trace
            .hops
            .iter()
            .find(|(_, hop)| hop.address == Some(destination))
        {
            println!("Destination arrival: confirmed at hop {position} ({destination})");
        } else {
            println!("Destination arrival: not confirmed ({destination})");
        }
    } else {
        println!("Destination arrival: not confirmed (destination address unavailable)");
    }
    println!("Unanswered probes do not establish packet loss.");
}

fn address_label(address: Option<IpAddr>) -> String {
    address.map_or_else(|| "unknown".into(), |address| address.to_string())
}

fn comparison_lines(current: &Trace, earlier: &Trace) -> Vec<String> {
    let mut changes = Vec::new();
    for (position, hop) in &current.hops {
        match earlier.hops.get(position) {
            None => changes.push(format!(
                "Hop {position} added: {}",
                address_label(hop.address)
            )),
            Some(previous) if previous.address != hop.address => changes.push(format!(
                "Hop {position} address changed: {} -> {}",
                address_label(previous.address),
                address_label(hop.address)
            )),
            _ => {}
        }
    }
    for (position, hop) in &earlier.hops {
        if !current.hops.contains_key(position) {
            changes.push(format!(
                "Hop {position} removed: {}",
                address_label(hop.address)
            ));
        }
    }
    changes
}

fn run(arguments: Arguments) -> Result<(), String> {
    let trace = read_trace(&arguments.input)?;
    let earlier = arguments.compare.as_ref().map(read_trace).transpose()?;
    print_trace(&trace);
    if let Some(earlier) = earlier {
        println!("Comparison: earlier report -> current report");
        let changes = comparison_lines(&trace, &earlier);
        if changes.is_empty() {
            println!("No router address or hop position changes.");
        }
        for change in changes {
            println!("{change}");
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Arguments::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT: &str = "Tracing route to example.test [203.0.113.10]\nover a maximum of 30 hops:\n\n  1    <1 ms    <1 ms     1 ms  gateway [192.168.1.1]\n  2     *        *        *     Request timed out.\n  3    12 ms    14 ms    13 ms  example.test [203.0.113.10]\n\nTrace complete.\n";

    #[test]
    fn preserves_bounds_and_unanswered_probes() {
        let trace = parse_trace(REPORT).unwrap();
        assert_eq!(trace.hops.len(), 3);
        assert_eq!(
            trace.hops[&1].probes,
            [
                Probe::LessThan(1),
                Probe::LessThan(1),
                Probe::Milliseconds(1)
            ]
        );
        assert_eq!(trace.hops[&1].probes[0].to_string(), "<1 ms");
        assert_eq!(trace.hops[&2].probes, [Probe::Unanswered; 3]);
        assert_eq!(trace.destination, trace.hops[&3].address);
        assert!(trace.complete);
    }

    #[test]
    fn rejects_malformed_probes_with_line_numbers() {
        for bad in ["fast ms", "1 us", "<fast ms", "18446744073709551616 ms"] {
            let report = REPORT.replacen("<1 ms", bad, 1);
            assert!(
                parse_trace(&report)
                    .unwrap_err()
                    .starts_with("line 4: probe 1:")
            );
        }
        assert!(parse_trace("1 * *\n").unwrap_err().contains("probe 3"));
        assert!(parse_trace("1 1 ms 2 ms 3 ms 4 ms\n").is_err());
    }

    #[test]
    fn rejects_missing_and_duplicate_rows() {
        assert!(
            parse_trace("Trace complete.\n")
                .unwrap_err()
                .contains("line 1: missing hop rows")
        );
        assert!(
            parse_trace("1 * * *\n1 * * *\n")
                .unwrap_err()
                .contains("line 2: duplicate hop number 1")
        );
        assert!(
            parse_trace("1 * * *\n3 * * *\n")
                .unwrap_err()
                .contains("line 2: missing hop row 2")
        );
        assert!(parse_trace("2 * * *\n").is_err());
    }

    #[test]
    fn recognises_ipv6_and_completion_without_arrival() {
        let trace = parse_trace("\u{feff}Tracing route to target\r\n[2001:db8::2]\r\nover a maximum of 30 hops:\r\n1 < 1 ms 0 ms * router [2001:db8::1]\r\n2 * * *\r\nTrace complete.\r\n").unwrap();
        assert_eq!(trace.destination, Some("2001:db8::2".parse().unwrap()));
        assert_eq!(trace.hops[&1].address, Some("2001:db8::1".parse().unwrap()));
        assert!(trace.complete);
        assert!(
            !trace
                .hops
                .values()
                .any(|hop| hop.address == trace.destination)
        );
        let unfinished = parse_trace("1 1 ms 2 ms 3 ms 2001:db8::2\n").unwrap();
        assert!(!unfinished.complete);
        assert_eq!(unfinished.hops[&1].address, trace.destination);
    }

    #[test]
    fn compares_addresses_and_positions_ignoring_hostnames() {
        let earlier = parse_trace(REPORT).unwrap();
        let renamed = parse_trace(&REPORT.replace("gateway", "renamed")).unwrap();
        assert!(comparison_lines(&renamed, &earlier).is_empty());
        let changed = parse_trace("1 * * * 192.168.1.2\n2 * * *\n").unwrap();
        assert_eq!(
            comparison_lines(&changed, &earlier),
            vec![
                "Hop 1 address changed: 192.168.1.1 -> 192.168.1.2",
                "Hop 3 removed: 203.0.113.10"
            ]
        );
        assert_eq!(
            comparison_lines(&earlier, &changed),
            vec![
                "Hop 1 address changed: 192.168.1.2 -> 192.168.1.1",
                "Hop 3 added: 203.0.113.10"
            ]
        );
    }
}
