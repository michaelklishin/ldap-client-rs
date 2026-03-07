// SPDX-License-Identifier: MIT OR Apache-2.0

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use ldap_client_ber::{BerReader, BerWriter};
use ldap_client_proto::{Dn, Filter};

fn bench_parse_simple(c: &mut Criterion) {
    c.bench_function("filter_parse_simple_eq", |b| {
        b.iter(|| {
            let _ = Filter::parse(black_box("(cn=admin)")).unwrap();
        });
    });
}

fn bench_parse_complex(c: &mut Criterion) {
    let filter = "(&(objectClass=inetOrgPerson)(|(cn=admin)(cn=user*))(mail=*@example.com))";
    c.bench_function("filter_parse_complex", |b| {
        b.iter(|| {
            let _ = Filter::parse(black_box(filter)).unwrap();
        });
    });
}

fn bench_to_string(c: &mut Criterion) {
    let filter = Filter::and(vec![
        Filter::eq("objectClass", "inetOrgPerson"),
        Filter::or(vec![
            Filter::eq("cn", "admin"),
            Filter::substring("cn", Some("user".into()), vec![], None),
        ]),
        Filter::present("mail"),
    ]);

    c.bench_function("filter_to_string", |b| {
        b.iter(|| {
            let _ = black_box(&filter).to_filter_string();
        });
    });
}

fn bench_ber_encode(c: &mut Criterion) {
    let filter = Filter::and(vec![
        Filter::eq("objectClass", "inetOrgPerson"),
        Filter::present("mail"),
        Filter::gte("uidNumber", "1000"),
    ]);

    c.bench_function("filter_ber_encode", |b| {
        b.iter(|| {
            let mut w = BerWriter::new();
            black_box(&filter).encode(&mut w);
            black_box(w.into_bytes());
        });
    });
}

fn bench_escape_value(c: &mut Criterion) {
    let value = "John (\"Johnny\") Doe\\Smith";
    c.bench_function("filter_escape_value", |b| {
        b.iter(|| {
            let _ = Filter::escape_value(black_box(value));
        });
    });
}

fn bench_ber_decode(c: &mut Criterion) {
    let filter = Filter::and(vec![
        Filter::eq("objectClass", "inetOrgPerson"),
        Filter::present("mail"),
        Filter::gte("uidNumber", "1000"),
    ]);
    let mut w = BerWriter::new();
    filter.encode(&mut w);
    let data = w.into_bytes();

    c.bench_function("filter_ber_decode", |b| {
        b.iter(|| {
            let mut r = BerReader::new(black_box(&data));
            let _ = Filter::decode(&mut r).unwrap();
        });
    });
}

fn bench_dn_parse(c: &mut Criterion) {
    let dn = "cn=John Doe+uid=jdoe,ou=People,dc=example,dc=com";
    c.bench_function("dn_parse", |b| {
        b.iter(|| {
            let _ = Dn::parse(black_box(dn)).unwrap();
        });
    });
}

fn bench_dn_display(c: &mut Criterion) {
    let dn = Dn::parse("cn=John Doe+uid=jdoe,ou=People,dc=example,dc=com").unwrap();
    c.bench_function("dn_display", |b| {
        b.iter(|| {
            let _ = black_box(&dn).to_string();
        });
    });
}

criterion_group!(
    benches,
    bench_parse_simple,
    bench_parse_complex,
    bench_to_string,
    bench_ber_encode,
    bench_escape_value,
    bench_ber_decode,
    bench_dn_parse,
    bench_dn_display
);
criterion_main!(benches);
