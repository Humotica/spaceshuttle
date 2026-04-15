//! Financial Triage Levels — matching triage_financial.py
//!
//! L0 (auto):     amount < 50 EUR, low-risk actions
//! L1 (operator): 50-500 EUR, or medium-risk actions
//! L2 (senior):   500-5000 EUR, or high-risk actions
//! L3 (ceremony): > 5000 EUR, or critical actions (account close, bulk transfer)

/// Triage levels matching the Python backend
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriageLevel {
    L0Auto = 0,
    L1Operator = 1,
    L2Senior = 2,
    L3Ceremony = 3,
}

/// Evaluate triage level for a financial action.
///
/// amount: in EUR (e.g., 500.0)
/// action: the financial intent (e.g., "transfer", "check", "receipt", "close")
pub fn evaluate(amount: f64, action: &str) -> u8 {
    let level = match action {
        // Critical actions always L3
        "close" | "account_close" | "bulk_transfer" => TriageLevel::L3Ceremony,

        // High-risk actions: at least L2
        "transfer" | "payment" | "withdrawal" => {
            if amount > 5000.0 {
                TriageLevel::L3Ceremony
            } else if amount > 500.0 {
                TriageLevel::L2Senior
            } else if amount > 50.0 {
                TriageLevel::L1Operator
            } else {
                TriageLevel::L0Auto
            }
        }

        // Medium-risk: receipt scan, categorization
        "receipt" | "categorize" | "budget" => {
            if amount > 5000.0 {
                TriageLevel::L2Senior
            } else if amount > 500.0 {
                TriageLevel::L1Operator
            } else {
                TriageLevel::L0Auto
            }
        }

        // Low-risk: check balance, list transactions
        "check" | "balance" | "list" | "history" => TriageLevel::L0Auto,

        // Unknown: default to L1 for safety
        _ => {
            if amount > 5000.0 {
                TriageLevel::L3Ceremony
            } else if amount > 500.0 {
                TriageLevel::L2Senior
            } else {
                TriageLevel::L1Operator
            }
        }
    };

    level as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_transfer_is_auto() {
        assert_eq!(evaluate(10.0, "transfer"), 0); // L0
    }

    #[test]
    fn medium_transfer_is_operator() {
        assert_eq!(evaluate(200.0, "transfer"), 1); // L1
    }

    #[test]
    fn large_transfer_is_senior() {
        assert_eq!(evaluate(2000.0, "transfer"), 2); // L2
    }

    #[test]
    fn huge_transfer_is_ceremony() {
        assert_eq!(evaluate(10000.0, "transfer"), 3); // L3
    }

    #[test]
    fn account_close_always_ceremony() {
        assert_eq!(evaluate(0.0, "close"), 3); // L3
    }

    #[test]
    fn balance_check_always_auto() {
        assert_eq!(evaluate(999999.0, "check"), 0); // L0
    }

    #[test]
    fn receipt_medium_amount() {
        assert_eq!(evaluate(600.0, "receipt"), 1); // L1
    }
}
