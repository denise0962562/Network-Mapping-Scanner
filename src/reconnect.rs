use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnectionState {
    Connecting,
    Online,
    Reconnecting,
    AuthRejected,
    PolicyBlocked,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RetryPolicy {
    initial: Duration,
    maximum: Duration,
}

impl RetryPolicy {
    pub(crate) fn new(initial: Duration, maximum: Duration) -> Self {
        Self { initial, maximum }
    }
}

pub(crate) struct Backoff {
    policy: RetryPolicy,
    failures: u32,
}

impl Backoff {
    pub(crate) fn new(policy: RetryPolicy) -> Self {
        Self {
            policy,
            failures: 0,
        }
    }

    pub(crate) fn reset(&mut self) {
        self.failures = 0;
    }

    pub(crate) fn next_delay(
        &mut self,
        maximum_override: Option<Duration>,
        retry_after: Option<Duration>,
    ) -> Duration {
        self.failures = self.failures.saturating_add(1);
        if let Some(retry_after) = retry_after {
            return retry_after;
        }
        let maximum = maximum_override
            .unwrap_or(self.policy.maximum)
            .min(self.policy.maximum);
        let shift = self.failures.saturating_sub(1).min(31);
        let exponential = self
            .policy
            .initial
            .checked_mul(1u32 << shift)
            .unwrap_or(maximum)
            .min(maximum);
        equal_jitter(exponential, jitter_sample())
    }

    pub(crate) fn failures(&self) -> u32 {
        self.failures
    }
}

fn jitter_sample() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos()
        .into()
}

fn equal_jitter(delay: Duration, sample: u64) -> Duration {
    let millis = delay.as_millis().min(u128::from(u64::MAX)) as u64;
    if millis <= 1 {
        return delay;
    }
    let half = millis / 2;
    Duration::from_millis(half + sample % (millis - half + 1))
}

#[cfg(test)]
mod tests {
    use super::{Backoff, RetryPolicy, equal_jitter};
    use std::time::Duration;

    #[test]
    fn exponential_backoff_is_capped_and_resettable() {
        let mut backoff = Backoff::new(RetryPolicy::new(
            Duration::from_secs(2),
            Duration::from_secs(8),
        ));
        for expected_max in [2, 4, 8, 8] {
            let delay = backoff.next_delay(None, None);
            assert!(delay >= Duration::from_secs(expected_max / 2));
            assert!(delay <= Duration::from_secs(expected_max));
        }
        backoff.reset();
        assert_eq!(backoff.failures(), 0);
    }

    #[test]
    fn retry_after_takes_precedence() {
        let mut backoff = Backoff::new(RetryPolicy::new(
            Duration::from_secs(1),
            Duration::from_secs(60),
        ));
        assert_eq!(
            backoff.next_delay(None, Some(Duration::from_secs(90))),
            Duration::from_secs(90)
        );
    }

    #[test]
    fn equal_jitter_never_creates_a_zero_delay() {
        assert_eq!(
            equal_jitter(Duration::from_secs(2), 0),
            Duration::from_secs(1)
        );
    }
}
