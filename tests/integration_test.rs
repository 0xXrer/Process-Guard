#[cfg(test)]
mod tests {
    use super::*;
    use process_guard::{ProcessGuard, InjectionType};

    #[tokio::test]
    async fn test_guard_creation() {
        let guard = ProcessGuard::new().await;
        assert!(guard.is_ok());
    }

    #[tokio::test]
    async fn test_detection_cache() {
        use process_guard::detector::{InjectionDetector, Detection};
        
        let detector = InjectionDetector::new();
        let detection = Detection {
            injection_type: InjectionType::ProcessHollowing,
            confidence: 0.95,
            timestamp: 1234567890,
            details: "Test detection".to_string(),
        };
        
        detector.detection_cache.insert(1234, vec![detection.clone()]);
        
        assert!(detector.detection_cache.contains_key(&1234));
        let cached = detector.detection_cache.get(&1234).unwrap();
        assert_eq!(cached.len(), 1);
        assert_eq!(cached[0].confidence, 0.95);
    }

    #[test]
    fn test_ml_features() {
        use process_guard::ml::ProcessFeatures;
        
        let features = ProcessFeatures {
            memory_usage: 0.5,
            thread_count: 0.2,
            handle_count: 0.3,
            cpu_usage: 0.1,
            network_activity: 0.05,
            file_operations: 0.02,
            registry_operations: 0.01,
            injection_indicators: 0.8,
        };
        
        assert!(features.injection_indicators > 0.7);
    }
}