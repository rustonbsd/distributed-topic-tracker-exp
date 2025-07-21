pub mod p01;

pub fn unix_minute(minute_offset: i64) -> u64 {
    ((chrono::Utc::now().timestamp() as f64 / 60.0f64).floor() as i64 + minute_offset) as u64
}
