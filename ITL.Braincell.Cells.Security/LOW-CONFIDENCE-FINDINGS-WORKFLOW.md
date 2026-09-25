# Low-Confidence Findings Workflow

**Objective**: Develop a comprehensive system to identify, verify, and escalate security findings that individual detectors flag with low confidence, but may collectively indicate real vulnerabilities.

**Problem**: Not all security vulnerabilities are obvious. Some emerge from:
- Multiple weak signals converging
- Unusual code patterns (not matching known CVE signatures)
- Subtle logic flaws requiring deep analysis
- Emerging attack techniques (not yet in databases)

**Solution**: Build a multi-layered confidence framework that:
1. Combines weak signals for stronger detection
2. Clusters similar findings for pattern recognition
3. Prioritizes human review intelligently
4. Learns from verification feedback
5. Refines confidence using Bayesian reasoning

---

## Table of Contents

1. [Confidence Spectrum](#confidence-spectrum)
2. [Ensemble Voting System](#ensemble-voting-system)
3. [Confidence Scoring Framework](#confidence-scoring-framework)
4. [Confidence-Based Routing](#confidence-based-routing)
5. [Clustering Low-Confidence Findings](#clustering-low-confidence-findings)
6. [Pattern Database Learning](#pattern-database-learning)
7. [Human-in-the-Loop Verification](#human-in-the-loop-verification)
8. [Confidence Decay Over Time](#confidence-decay-over-time)
9. [Bayesian Confidence Updates](#bayesian-confidence-updates)
10. [ORM Models](#orm-models)
11. [Service Implementation](#service-implementation)
12. [Complete Workflow](#complete-workflow)
13. [Success Metrics](#success-metrics)

---

## Confidence Spectrum

### The Confidence Pyramid

```
                        HIGH CONFIDENCE (>95%)
                   ▲ Automatic Flagging
                  │ Immediate Action
                  │ ─────────────────────
                  │
              MEDIUM-HIGH (70-90%)
              Flag + Verification Queue
              ─────────────────────
              │
          MEDIUM (50-70%)
          Collect & Cluster
          ─────────────────
          │
      LOW (<50%)
      Archive & Learn
      ─────────────────
```

### Vulnerability Classes by Confidence

| Class | Confidence Range | Examples | Action |
|-------|------------------|----------|--------|
| **Definite** | >95% | SQL Injection with entry-to-sink flow, Hardcoded API keys | Immediate flag, notify team |
| **Likely** | 70-95% | Suspicious function patterns, Multiple validation failures | Queue for verification |
| **Possible** | 50-70% | Behavioral anomalies, Mild code complexity outliers | Cluster & pattern match |
| **Uncertain** | <50% | Entropy anomalies, Loose behavioral patterns | Archive for ML training |
| **Experimental** | <20% | Zero-day pattern detection, Novel attack techniques | Contribute to emerging technique database |

---

## Ensemble Voting System

### Architecture: Multiple Weak Signals → Strong Signal

The ensemble approach runs **8 independent detectors** and votes on findings:

```
┌─────────────────────────────────────────────────────────────────┐
│ CODE UNDER ANALYSIS                                             │
└─────────────────────────────────────────────────────────────────┘
                            ↓
        ┌───────────────────┼───────────────────┐
        ↓                   ↓                   ↓ ... 8 detectors
    ┌────────────┐  ┌────────────┐  ┌────────────┐
    │ Static     │  │ AST        │  │ ML         │
    │ Analysis   │  │ Analysis   │  │ Pattern    │
    │ (Regex)    │  │ (Structure)│  │ Matching   │
    └────────────┘  └────────────┘  └────────────┘
            ↓                ↓                ↓
            └────────────────┼────────────────┘
                             ↓
                    ┌─────────────────┐
                    │ VOTING ENGINE   │
                    │                 │
                    │ Count votes     │
                    │ Calculate conf  │
                    │ Aggregate score │
                    └─────────────────┘
                             ↓
                    ┌─────────────────┐
                    │ CONFIDENCE      │
                    │ SCORE           │
                    │ (0-100%)        │
                    └─────────────────┘
```

### The 8 Detectors

```python
class EnsembleVulnerabilityDetector:
    """Eight independent detection methods"""
    
    def __init__(self):
        self.detectors = [
            # 1. Static Analysis: Regex-based pattern matching
            StaticAnalysisDetector(),
            
            # 2. AST Analysis: Code structure and control flow
            ASTAnalysisDetector(),
            
            # 3. ML Pattern Matching: Trained on known vulnerabilities
            MLPatternDetector(),
            
            # 4. Entropy Analysis: Obfuscation and compression detection
            EntropyAnalysisDetector(),
            
            # 5. Control Flow Analysis: Data flow and taint tracking
            ControlFlowAnalysisDetector(),
            
            # 6. Behavioral Anomaly: Unusual code patterns
            BehavioralAnomalyDetector(),
            
            # 7. Research Correlation: Links to published research
            ResearchCorrelationDetector(),
            
            # 8. Complexity Analysis: Suspiciously complex code
            ComplexityAnalysisDetector(),
        ]
    
    async def detect_with_ensemble(self, code: str, file_path: str) -> dict:
        """Run all detectors, combine results"""
        
        # Run in parallel for speed
        results = await asyncio.gather(*[
            detector.analyze(code, file_path)
            for detector in self.detectors
        ])
        
        # Aggregate findings
        vulnerabilities = self._aggregate_findings(results)
        
        # Calculate ensemble confidence
        for vuln_key in vulnerabilities:
            vuln = vulnerabilities[vuln_key]
            vuln['ensemble_confidence'] = self._calculate_confidence(vuln)
            vuln['strength'] = self._classify_strength(vuln['ensemble_confidence'])
        
        return vulnerabilities
    
    def _aggregate_findings(self, detector_results: list) -> dict:
        """Combine findings from all detectors"""
        
        vulnerabilities = {}
        
        for detector_idx, detector_result in enumerate(detector_results):
            detector_name = self.detectors[detector_idx].__class__.__name__
            
            for finding in detector_result.get('findings', []):
                # Create unique key: vulnerability type + location
                vuln_key = f"{finding['type']}_{finding['line']}"
                
                if vuln_key not in vulnerabilities:
                    vulnerabilities[vuln_key] = {
                        'type': finding['type'],
                        'line': finding['line'],
                        'file': finding['file'],
                        'detectors_voting': [],
                        'signals': [],
                        'vote_count': 0
                    }
                
                # Record this detector's vote
                vulnerabilities[vuln_key]['detectors_voting'].append(detector_name)
                vulnerabilities[vuln_key]['signals'].append(finding)
                vulnerabilities[vuln_key]['vote_count'] += 1
        
        return vulnerabilities
    
    def _calculate_confidence(self, vuln_data: dict) -> float:
        """
        Confidence = (detectors_voting / total_detectors) * 100
        
        Example:
        - 7 out of 8 detectors agree → 87.5% confidence
        - 5 out of 8 detectors agree → 62.5% confidence
        - 3 out of 8 detectors agree → 37.5% confidence
        """
        
        vote_count = vuln_data['vote_count']
        total_detectors = len(self.detectors)
        
        return (vote_count / total_detectors) * 100
    
    def _classify_strength(self, confidence: float) -> str:
        """Classify based on detector agreement"""
        
        if confidence >= 87.5:  # 7/8 detectors
            return "STRONG"
        elif confidence >= 62.5:  # 5/8 detectors
            return "MODERATE"
        elif confidence >= 37.5:  # 3/8 detectors
            return "WEAK"
        else:
            return "SUSPICIOUS"
```

### Example Ensemble Vote

```
Finding: Potential Logic Bypass in authorization.py:145

Detector Results:
┌────────────────────────────────────────┐
│ StaticAnalysisDetector     ✓ FLAGGED   │  (Regex: "if role ==" without else)
│ ASTAnalysisDetector        ✓ FLAGGED   │  (Structure: incomplete condition)
│ MLPatternDetector          ✓ FLAGGED   │  (Similar to known logic bugs)
│ EntropyAnalysisDetector    ✗ NONE      │  (No obfuscation detected)
│ ControlFlowAnalysisDetector ✓ FLAGGED  │  (Unreachable code path)
│ BehavioralAnomalyDetector  ✓ FLAGGED   │  (Unusual pattern detected)
│ ResearchCorrelationDetector ✓ FLAGGED  │  (Matches OWASP broken auth)
│ ComplexityAnalysisDetector ✗ NONE      │  (Low complexity, not suspicious)
└────────────────────────────────────────┘

Vote Count: 6/8 detectors agree
Ensemble Confidence: 75%
Strength: MODERATE
Action: Queue for manual verification
```

---

## Confidence Scoring Framework

### Multi-Factor Confidence Calculation

Instead of a single confidence number, calculate confidence with breakdown:

```python
class ConfidenceScorer:
    """
    Base confidence from detection methods
    + Evidence strength
    + Pattern specificity
    + Code complexity
    - False positive history
    = Final confidence score
    """
    
    def score_vulnerability(self, vuln: dict) -> dict:
        """Calculate confidence with factor breakdown"""
        
        score = 0.0
        factors = {}
        weights = {
            'detector_agreement': 0.40,      # 40% weight
            'pattern_specificity': 0.25,    # 25% weight
            'evidence_chain': 0.20,         # 20% weight
            'reliability': 0.15             # 15% weight
        }
        
        # Factor 1: Detector Agreement (40% weight)
        # How many detectors voted for this?
        detector_agreement = vuln['vote_count'] / 8
        factors['detector_agreement'] = detector_agreement * weights['detector_agreement']
        print(f"  Detector agreement: {detector_agreement:.1%} × 0.40 = {factors['detector_agreement']:.3f}")
        
        # Factor 2: Pattern Specificity (25% weight)
        # How specific is this pattern to this vulnerability?
        # Exact match = high specificity (1.0)
        # Loose match = low specificity (0.3)
        pattern_specificity = self._assess_pattern_specificity(vuln)
        factors['pattern_specificity'] = pattern_specificity * weights['pattern_specificity']
        print(f"  Pattern specificity: {pattern_specificity:.1%} × 0.25 = {factors['pattern_specificity']:.3f}")
        
        # Factor 3: Evidence Chain (20% weight)
        # Do we have corroborating evidence?
        # Entry point → data flow → sink all verified?
        evidence_chain = self._check_evidence_chain(vuln)
        factors['evidence_chain'] = evidence_chain * weights['evidence_chain']
        print(f"  Evidence chain: {evidence_chain:.1%} × 0.20 = {factors['evidence_chain']:.3f}")
        
        # Factor 4: Pattern Reliability (15% weight)
        # Historically, how often does this pattern indicate a real vulnerability?
        pattern_type = vuln['type']
        historical_accuracy = self._get_false_positive_rate(pattern_type)
        factors['reliability'] = historical_accuracy * weights['reliability']
        print(f"  Pattern reliability: {historical_accuracy:.1%} × 0.15 = {factors['reliability']:.3f}")
        
        # Total confidence (sum of weighted factors)
        total_confidence = sum(factors.values())
        
        return {
            'confidence': total_confidence,
            'percentage': f"{total_confidence * 100:.1f}%",
            'breakdown': factors,
            'meets_threshold': total_confidence >= 0.60
        }
    
    def _assess_pattern_specificity(self, vuln: dict) -> float:
        """How specific is this pattern?"""
        
        specificity_by_type = {
            # High specificity (few false positives)
            'exact_code_match': 0.95,
            'full_data_flow': 0.85,
            'entry_to_sink_complete': 0.80,
            
            # Medium specificity
            'partial_data_flow': 0.60,
            'dangerous_function_call': 0.50,
            'suspicious_pattern': 0.40,
            
            # Low specificity (many false positives)
            'entropy_anomaly': 0.20,
            'complexity_outlier': 0.15,
            'behavioral_anomaly': 0.10,
        }
        
        pattern_type = vuln.get('pattern_type')
        return specificity_by_type.get(pattern_type, 0.30)
    
    def _check_evidence_chain(self, vuln: dict) -> float:
        """Do we have complete evidence?"""
        
        chain_score = 0.0
        
        # Entry point identified?
        if vuln.get('entry_point'):
            chain_score += 0.33
        
        # Data flow traced?
        if vuln.get('data_flow_verified'):
            chain_score += 0.33
        
        # Sink (dangerous operation) found?
        if vuln.get('sink_function'):
            chain_score += 0.34
        
        return chain_score
    
    def _get_false_positive_rate(self, pattern_type: str) -> float:
        """
        Historical false positive rate for this pattern type
        Lower rate = higher reliability = higher weight
        """
        
        # Based on historical verification data
        false_positive_rates = {
            'SQL Injection': 0.02,        # 98% accurate historically
            'Command Injection': 0.03,
            'XXE': 0.05,
            'Logic Bypass': 0.15,        # 85% accurate
            'Race Condition': 0.20,
            'TOCTOU': 0.25,              # 75% accurate
            'Entropy Anomaly': 0.60,     # 40% accurate (many false positives)
            'Behavioral Anomaly': 0.70,  # 30% accurate
        }
        
        false_positive_rate = false_positive_rates.get(pattern_type, 0.50)
        reliability = 1.0 - false_positive_rate  # Convert to accuracy
        
        return reliability
```

### Confidence Breakdown Example

```
Vulnerability: "Potential SQL Injection" in auth.py:42

Factor Breakdown:
├─ Detector Agreement: 6/8 (75%) × 0.40 = 0.300
├─ Pattern Specificity: Full data flow (85%) × 0.25 = 0.213
├─ Evidence Chain: Entry point + flow + sink (100%) × 0.20 = 0.200
└─ Reliability: SQL Injection historically accurate (98%) × 0.15 = 0.147

Total Confidence: 0.860 = 86.0%
Status: MEETS THRESHOLD (≥60%)
Action: Queue for verification
```

---

## Confidence-Based Routing

### Automatic Action Based on Confidence

```python
class ConfidenceBasedRouter:
    """Route findings to appropriate action based on confidence"""
    
    async def handle_finding(self, vulnerability: dict):
        """Automatically route based on confidence level"""
        
        confidence = vulnerability['confidence']
        vuln_type = vulnerability['type']
        
        # ✅ TIER 1: HIGH CONFIDENCE (>90%)
        # Definite vulnerabilities → Immediate action
        if confidence > 0.90:
            await self._tier1_high_confidence(vulnerability)
        
        # ⚠️ TIER 2: MEDIUM-HIGH CONFIDENCE (70-90%)
        # Likely vulnerabilities → Flag + verify
        elif confidence > 0.70:
            await self._tier2_medium_high_confidence(vulnerability)
        
        # ⚠️ TIER 3: MEDIUM CONFIDENCE (50-70%)
        # Possible vulnerabilities → Collect + cluster
        elif confidence > 0.50:
            await self._tier3_medium_confidence(vulnerability)
        
        # ❌ TIER 4: LOW CONFIDENCE (<50%)
        # Uncertain findings → Archive + ML training
        else:
            await self._tier4_low_confidence(vulnerability)
    
    async def _tier1_high_confidence(self, vuln: dict):
        """High confidence: Definite vulnerabilities"""
        print(f"[TIER 1] Flagging as VULNERABILITY: {vuln['type']}")
        
        # Immediate actions
        await self.flag_as_vulnerability(vuln)
        await self.generate_poc(vuln)
        await self.notify_security_team_immediately(vuln)
        await self.create_github_issue(vuln, severity="CRITICAL")
        await self.start_exploitation_planning(vuln)
    
    async def _tier2_medium_high_confidence(self, vuln: dict):
        """Medium-high confidence: Likely vulnerabilities"""
        print(f"[TIER 2] Queueing for verification: {vuln['type']}")
        
        # Flag but request verification
        await self.flag_as_vulnerability(vuln)
        await self.add_to_verification_queue(vuln, priority=1)
        await self.request_manual_review(vuln)
        await self.notify_security_team_later(vuln, delay_minutes=60)
    
    async def _tier3_medium_confidence(self, vuln: dict):
        """Medium confidence: Possible vulnerabilities"""
        print(f"[TIER 3] Collecting for clustering: {vuln['type']}")
        
        # Hold for pattern analysis
        await self.save_to_low_confidence_pool(vuln)
        await self.cluster_similar_findings(vuln)
        
        # Check if cluster threshold is met
        cluster_size = await self.get_cluster_size(vuln)
        if cluster_size >= 5:
            # Multiple weak signals → escalate
            await self.escalate_cluster_to_tier2(vuln)
    
    async def _tier4_low_confidence(self, vuln: dict):
        """Low confidence: Uncertain findings"""
        print(f"[TIER 4] Archiving for pattern analysis: {vuln['type']}")
        
        # Archive but contribute to learning
        await self.archive_for_pattern_analysis(vuln)
        await self.contribute_to_ml_training_dataset(vuln)
        await self.update_pattern_statistics(vuln)
```

### Router Configuration Table

| Confidence | Status | Action | Timeline | Review |
|------------|--------|--------|----------|--------|
| >90% | CONFIRMED | Flag immediately, generate POC, notify team | Immediate | Auto |
| 70-90% | LIKELY | Flag, queue for review, estimate impact | 1 hour | Human |
| 50-70% | POSSIBLE | Collect, cluster, escalate if pattern found | 1 day | Pattern |
| <50% | UNCERTAIN | Archive, contribute to ML training | N/A | None |

---

## Clustering Low-Confidence Findings

### The Clustering Hypothesis

**Premise**: Many weak signals pointing to the same vulnerability type = strong signal

**Example**:
```
Low-confidence finding (35%): Suspicious entropy in function A
Low-confidence finding (40%): Suspicious entropy in function B  
Low-confidence finding (38%): Suspicious entropy in function C
... (pattern repeats 7 more times)

Individual signals: Weak
Aggregate signal: "File contains repeated suspicious patterns"
Action: Manual review file-wide (HIGH PRIORITY)
```

### Clustering Algorithm

```python
class LowConfidenceClusterer:
    """Group similar low-confidence findings"""
    
    async def cluster_findings(self, low_conf_vulns: list[dict]):
        """
        Group by:
        1. Vulnerability type
        2. File/module
        3. Confidence range
        4. Detector agreement pattern
        """
        
        clusters = {}
        
        for vuln in low_conf_vulns:
            # Create cluster key
            cluster_key = f"{vuln['type']}_{vuln['file']}"
            
            if cluster_key not in clusters:
                clusters[cluster_key] = {
                    'vulns': [],
                    'type': vuln['type'],
                    'file': vuln['file'],
                    'individual_confidences': [],
                    'cluster_size': 0,
                    'aggregate_confidence': 0.0
                }
            
            clusters[cluster_key]['vulns'].append(vuln)
            clusters[cluster_key]['individual_confidences'].append(vuln['confidence'])
            clusters[cluster_key]['cluster_size'] += 1
        
        # Analyze clusters
        escalated_count = 0
        
        for cluster_key, cluster_data in clusters.items():
            size = cluster_data['cluster_size']
            
            if size >= 5:
                # Sufficient clustering threshold
                aggregate = self._calculate_aggregate_confidence(
                    cluster_data['individual_confidences']
                )
                
                cluster_data['aggregate_confidence'] = aggregate
                
                if aggregate > 0.70:
                    # Escalate to tier 2
                    await self._escalate_cluster(cluster_data)
                    escalated_count += 1
                else:
                    # Not yet strong enough
                    await self._save_cluster_for_monitoring(cluster_data)
            else:
                # Keep collecting
                await self._save_cluster_for_monitoring(cluster_data)
        
        print(f"Clustered {len(clusters)} patterns, escalated {escalated_count}")
    
    def _calculate_aggregate_confidence(self, confidences: list[float]) -> float:
        """
        Average confidence + cluster bonus
        
        Bonus = log(cluster_size) / 10
        - Cluster of 5: log(5)/10 = 0.070
        - Cluster of 10: log(10)/10 = 0.100
        - Cluster of 20: log(20)/10 = 0.130
        """
        
        avg = sum(confidences) / len(confidences)
        cluster_size = len(confidences)
        
        # Bonus for repetition (sublinear growth)
        bonus = math.log(cluster_size + 1) / 10
        
        # Cap bonus at 0.2 (don't let weak signals become strong)
        bonus = min(bonus, 0.2)
        
        aggregate = min(avg + bonus, 0.99)  # Cap at 99%
        
        return aggregate
    
    async def _escalate_cluster(self, cluster_data: dict):
        """Escalate cluster to tier 2 for verification"""
        
        print(f"[CLUSTER ESCALATION]")
        print(f"  Type: {cluster_data['type']}")
        print(f"  File: {cluster_data['file']}")
        print(f"  Size: {cluster_data['cluster_size']} findings")
        print(f"  Aggregate Confidence: {cluster_data['aggregate_confidence']:.1%}")
        
        # Create cluster vulnerability
        cluster_vuln = {
            'is_cluster': True,
            'cluster_type': cluster_data['type'],
            'cluster_file': cluster_data['file'],
            'cluster_size': cluster_data['cluster_size'],
            'individual_vulns': cluster_data['vulns'],
            'aggregate_confidence': cluster_data['aggregate_confidence'],
            'finding': f"{cluster_data['cluster_size']}x {cluster_data['type']} pattern in {cluster_data['file']}"
        }
        
        # Treat as tier 2 medium-high confidence
        await self._tier2_medium_high_confidence(cluster_vuln)
```

### Clustering Example

```
BEFORE CLUSTERING:
├─ Finding 1: Entropy anomaly in auth.py:42 (confidence: 35%)
├─ Finding 2: Entropy anomaly in auth.py:87 (confidence: 38%)
├─ Finding 3: Entropy anomaly in auth.py:145 (confidence: 40%)
├─ Finding 4: Entropy anomaly in auth.py:201 (confidence: 32%)
├─ Finding 5: Entropy anomaly in auth.py:256 (confidence: 37%)
├─ Finding 6: Entropy anomaly in auth.py:312 (confidence: 41%)
├─ Finding 7: Entropy anomaly in auth.py:368 (confidence: 36%)
└─ Finding 8: Entropy anomaly in auth.py:424 (confidence: 39%)

CLUSTERING ANALYSIS:
├─ Cluster Key: "entropy_anomaly_auth.py"
├─ Cluster Size: 8 findings
├─ Average Confidence: 37.5%
├─ Cluster Bonus: log(8+1)/10 = 0.095
├─ Aggregate Confidence: 37.5% + 9.5% = 47.0%
└─ Decision: Still too weak (need >70%), continue collecting

AFTER 12 FINDINGS:
├─ Cluster Size: 12 findings
├─ Average Confidence: 38.2%
├─ Cluster Bonus: log(12+1)/10 = 0.114
├─ Aggregate Confidence: 38.2% + 11.4% = 49.6%
└─ Decision: Pattern getting stronger, monitor closely

AFTER 18 FINDINGS:
├─ Cluster Size: 18 findings
├─ Average Confidence: 38.9%
├─ Cluster Bonus: log(18+1)/10 = 0.127
├─ Aggregate Confidence: 38.9% + 12.7% = 51.6%
└─ Decision: Still need more evidence

ESCALATION TRIGGER: Combine with new signal
└─ Code review finds obfuscated code in same file
└─ Aggregate: 51.6% + obfuscation = ESCALATE TO TIER 2
```

---

## Pattern Database Learning

### Historical Accuracy Tracking

```python
class PatternConfidenceDatabase:
    """Learn which vulnerability patterns are actually real"""
    
    def __init__(self):
        self.pattern_stats = {}
    
    async def record_verification(self, finding_id: str, result: dict):
        """
        When a finding is verified:
        - True positive: pattern is correct
        - False positive: pattern is incorrect
        
        Update pattern accuracy statistics
        """
        
        finding = await self.get_finding(finding_id)
        pattern = finding['type']
        
        # Initialize pattern stats if needed
        if pattern not in self.pattern_stats:
            self.pattern_stats[pattern] = {
                'total_found': 0,
                'verified_true_positives': 0,
                'false_positives': 0,
                'accuracy': 0.0,
                'true_positive_rate': 0.0,
                'false_positive_rate': 1.0
            }
        
        stats = self.pattern_stats[pattern]
        stats['total_found'] += 1
        
        if result['is_valid']:
            stats['verified_true_positives'] += 1
        else:
            stats['false_positives'] += 1
        
        # Recalculate statistics
        total = stats['total_found']
        true = stats['verified_true_positives']
        false = stats['false_positives']
        
        stats['accuracy'] = true / total if total > 0 else 0.0
        stats['true_positive_rate'] = true / total if total > 0 else 0.0
        stats['false_positive_rate'] = false / total if total > 0 else 1.0
        
        print(f"Pattern '{pattern}':")
        print(f"  Total: {total}, True: {true}, False: {false}")
        print(f"  Accuracy: {stats['accuracy']:.1%}")
    
    def get_adjusted_confidence(
        self,
        pattern: str,
        base_confidence: float
    ) -> float:
        """
        Adjust confidence based on pattern's historical accuracy
        
        If pattern is historically 80% accurate:
        - Base confidence 60% → Adjusted to ~72%
        - Base confidence 50% → Adjusted to ~60%
        """
        
        if pattern not in self.pattern_stats:
            # No history yet
            return base_confidence
        
        historical_accuracy = self.pattern_stats[pattern]['accuracy']
        
        # If history says 30% are true positives:
        # adjustment = 0.30 - 0.5 = -0.20
        adjustment = historical_accuracy - 0.5
        
        # Apply adjustment capped at ±20%
        adjusted = base_confidence + (adjustment * 0.20)
        
        # Clamp to 0.0-1.0 range
        return max(0.0, min(1.0, adjusted))
    
    def get_pattern_reliability(self, pattern: str) -> dict:
        """Get reliability metrics for a pattern"""
        
        if pattern not in self.pattern_stats:
            return {
                'has_data': False,
                'recommendation': "No historical data yet"
            }
        
        stats = self.pattern_stats[pattern]
        
        return {
            'has_data': True,
            'total_findings': stats['total_found'],
            'true_positives': stats['verified_true_positives'],
            'false_positives': stats['false_positives'],
            'accuracy': stats['accuracy'],
            'recommendation': self._get_recommendation(stats['accuracy'])
        }
    
    def _get_recommendation(self, accuracy: float) -> str:
        """Recommendation based on accuracy"""
        
        if accuracy >= 0.85:
            return "HIGHLY RELIABLE - Use for high-confidence decisions"
        elif accuracy >= 0.70:
            return "RELIABLE - Queue for standard verification"
        elif accuracy >= 0.50:
            return "MODERATE - Cluster and monitor"
        else:
            return "UNRELIABLE - Archive for ML retraining"
```

### Pattern Statistics Examples

```
PATTERN: SQL Injection
├─ Total Findings: 47
├─ True Positives: 46
├─ False Positives: 1
├─ Accuracy: 97.9%
├─ Status: HIGHLY RELIABLE
└─ Action: Immediate flagging recommended

PATTERN: Logic Bypass
├─ Total Findings: 34
├─ True Positives: 26
├─ False Positives: 8
├─ Accuracy: 76.5%
├─ Status: RELIABLE
└─ Action: Queue for verification

PATTERN: Entropy Anomaly
├─ Total Findings: 89
├─ True Positives: 28
├─ False Positives: 61
├─ Accuracy: 31.5%
├─ Status: UNRELIABLE
└─ Action: Only use in clusters (3+ occurrences)

PATTERN: Behavioral Anomaly (New)
├─ Total Findings: 5
├─ True Positives: 2
├─ False Positives: 3
├─ Accuracy: 40.0%
├─ Status: INSUFFICIENT DATA
└─ Action: Collect more samples before deciding
```

---

## Human-in-the-Loop Verification

### Intelligent Verification Queue

```python
class VerificationQueue:
    """Smart queue for human review of uncertain findings"""
    
    async def prioritize_for_review(self, vulnerability: dict):
        """
        Not all uncertain findings are equally worth reviewing.
        Prioritize high-impact ones first.
        """
        
        # Calculate priority score
        priority_score = self._calculate_priority(vulnerability)
        
        # Prepare review package
        review_item = {
            'vulnerability': vulnerability,
            'priority_score': priority_score,
            'estimated_review_time_minutes': 5,
            'context': {
                'function_code': self._extract_function_context(vulnerability),
                'data_flow': vulnerability.get('data_flow_path'),
                'similar_findings': await self._find_similar_findings(vulnerability),
                'cwe_details': self._get_cwe_documentation(vulnerability.get('cwe_id'))
            },
            'reviewer_prompt': self._generate_reviewer_prompt(vulnerability),
            'suggested_verdict': self._suggest_verdict(vulnerability)
        }
        
        # Add to queue
        await self.db.add(review_item)
        await self.db.commit()
        
        return review_item
    
    def _calculate_priority(self, vulnerability: dict) -> float:
        """Calculate review priority score (0.0-1.0)"""
        
        score = 0.0
        
        # Factor 1: Severity if true (40%)
        severity_weight = {
            'CRITICAL': 0.40,
            'HIGH': 0.30,
            'MEDIUM': 0.15,
            'LOW': 0.05
        }
        severity = vulnerability.get('severity', 'MEDIUM')
        score += severity_weight.get(severity, 0.10)
        
        # Factor 2: Detector agreement (30%)
        detector_count = len(vulnerability.get('detectors_voting', []))
        detector_score = (detector_count / 8) * 0.30
        score += detector_score
        
        # Factor 3: Potential impact (20%)
        if vulnerability.get('can_access_sensitive_data'):
            score += 0.20
        elif vulnerability.get('can_cause_dos'):
            score += 0.10
        elif vulnerability.get('can_bypass_auth'):
            score += 0.15
        
        # Factor 4: Cluster/pattern indication (10%)
        similar_count = len(vulnerability.get('similar_findings', []))
        if similar_count > 0:
            score += min(similar_count / 10, 0.10)
        
        return min(score, 1.0)
    
    def _generate_reviewer_prompt(self, vulnerability: dict) -> str:
        """Generate prompt for human reviewer"""
        
        return f"""
Review Vulnerability Finding

TYPE: {vulnerability['type']}
FILE: {vulnerability['file']}
LINE: {vulnerability['line']}
CONFIDENCE: {vulnerability['confidence']:.1%}
DETECTORS: {len(vulnerability.get('detectors_voting', []))} out of 8 agree

DESCRIPTION:
{vulnerability.get('description', 'N/A')}

VULNERABLE CODE:
{vulnerability.get('code_snippet', 'N/A')}

DETECTOR SIGNALS:
{chr(10).join(f"  • {sig}" for sig in vulnerability.get('signals', []))}

QUESTION FOR REVIEWER:
Is this a real vulnerability? 
  - YES: This is a valid security issue
  - NO: This is a false positive
  - MAYBE: Needs more investigation
  
PLEASE PROVIDE:
  1. Your verdict (YES/NO/MAYBE)
  2. Confidence in your verdict (0-100%)
  3. Explanation of your reasoning
  4. Any additional context
"""
    
    def _suggest_verdict(self, vulnerability: dict) -> str:
        """Suggest verdict based on signals"""
        
        if vulnerability['confidence'] > 0.75:
            return "Likely TRUE - Multiple signals agree"
        elif vulnerability['confidence'] > 0.50:
            return "Possibly TRUE - Mixed signals, needs review"
        else:
            return "Likely FALSE - Weak signals, probably false positive"
```

### Verification Queue Table

| Priority | Findings | Review Time | Batch Size |
|----------|----------|-------------|-----------|
| 1 (Highest) | Critical severity + 5+ detector votes | 3 min | 20 |
| 2 | High severity + 3+ detector votes | 5 min | 30 |
| 3 | Medium severity + 3+ detector votes | 5 min | 40 |
| 4 | Clustered patterns (5+ occurrences) | 8 min | 25 |
| 5 (Lowest) | Low severity + 1-2 detector votes | 10 min | 10 |

---

## Confidence Decay Over Time

### The Problem: Stale Findings

```
Recent finding (1 day old) at 60% confidence
  → Credible, should review soon

Old finding (6 months old) at 60% confidence
  → Probably false positive, likely irrelevant
```

### Decay Algorithm

```python
class ConfidenceDecay:
    """Reduce confidence for old findings if not verified"""
    
    async def apply_confidence_decay(self, vulnerability: dict):
        """
        Confidence decays over time if not verified.
        
        Decay rate: -1% per month (optional: -2% per month for very low confidence)
        """
        
        created_at = vulnerability['created_at']
        days_old = (datetime.now() - created_at).days
        months_old = days_old / 30
        
        # Decay factor: -1% per month
        decay_rate = months_old * 0.01
        
        original_confidence = vulnerability['confidence']
        decayed_confidence = original_confidence - decay_rate
        
        # Clamp to 0.0-1.0
        decayed_confidence = max(0.0, min(1.0, decayed_confidence))
        
        if decayed_confidence < original_confidence:
            # Confidence changed, update record
            await self.update_finding_confidence(
                vulnerability.id,
                decayed_confidence,
                reason=f"Decayed by {decay_rate:.1%} over {months_old:.1f} months"
            )
        
        return {
            'original_confidence': original_confidence,
            'decayed_confidence': decayed_confidence,
            'age_days': days_old,
            'decay_rate': decay_rate,
            'archived': decayed_confidence < 0.30
        }
    
    async def archive_stale_unverified(self):
        """Archive very old, unverified, low-confidence findings"""
        
        cutoff_date = datetime.now() - timedelta(days=180)  # 6 months
        
        findings_to_archive = await self.db.execute(
            select(LowConfidenceFinding).where(
                (LowConfidenceFinding.created_at < cutoff_date) &
                (LowConfidenceFinding.verified == False) &
                (LowConfidenceFinding.current_confidence < 0.40)
            )
        )
        
        count = 0
        for finding in findings_to_archive.scalars():
            await self.archive_finding(finding, reason="Stale unverified finding")
            count += 1
        
        print(f"Archived {count} stale findings")
```

### Decay Timeline Example

```
FINDING: Entropy Anomaly in utils.py:45
├─ Created: 2026-02-03
├─ Original Confidence: 45%

DAY 1 (2026-02-03):
├─ Confidence: 45%
└─ Status: QUEUED FOR REVIEW

MONTH 1 (2026-03-03):
├─ Decay: -1%
├─ Confidence: 44%
└─ Status: IN LOW-CONFIDENCE POOL

MONTH 3 (2026-05-03):
├─ Decay: -3%
├─ Confidence: 42%
└─ Status: STILL IN POOL

MONTH 6 (2026-08-03):
├─ Decay: -6%
├─ Confidence: 39%
└─ Status: STILL IN POOL

MONTH 9 (2026-11-03):
├─ Decay: -9%
├─ Confidence: 36%
└─ Status: MONITOR FOR CLUSTERING

MONTH 12 (2026-12-03):
├─ Decay: -12%
├─ Confidence: 33%
└─ Status: AGING OUT

MONTH 15 (2027-03-03):
├─ Decay: -15%
├─ Confidence: 30% (threshold)
└─ Status: ARCHIVED (if still unverified)
```

---

## Bayesian Confidence Updates

### Using Bayes' Theorem for Confidence Refinement

```python
class BayesianConfidenceUpdater:
    """
    Bayes: P(Vulnerability | Evidence) 
         = P(Evidence | Vulnerability) × P(Vulnerability) / P(Evidence)
    
    Update confidence as new evidence emerges
    """
    
    def update_with_new_evidence(
        self,
        prior_confidence: float,
        new_evidence: dict
    ) -> float:
        """
        prior_confidence: Initial confidence (before new evidence)
        new_evidence: New findings that support or refute
        
        Returns: Updated posterior confidence
        """
        
        # Prior probability
        p_vulnerability = prior_confidence
        
        # Likelihood: How much does evidence support vulnerability?
        # If evidence strongly supports: 0.9
        # If evidence weakly supports: 0.5
        # If evidence contradicts: 0.1
        p_evidence_given_vuln = new_evidence.get('likelihood', 0.7)
        
        # Base rate: How common are vulnerabilities of this type?
        # (From historical pattern database)
        base_rate = self._get_base_rate(new_evidence['type'])
        
        # Likelihood if NOT vulnerable
        p_evidence_given_not_vuln = 1.0 - p_evidence_given_vuln
        
        # Total probability of evidence
        # P(Evidence) = P(E|V) × P(V) + P(E|¬V) × P(¬V)
        p_evidence = (
            p_evidence_given_vuln * p_vulnerability +
            p_evidence_given_not_vuln * (1 - p_vulnerability)
        )
        
        # Bayes theorem: Posterior = Likelihood × Prior / Evidence
        if p_evidence > 0:
            posterior = (p_evidence_given_vuln * p_vulnerability) / p_evidence
        else:
            posterior = p_vulnerability
        
        return posterior
    
    def _get_base_rate(self, vulnerability_type: str) -> float:
        """
        What % of repos contain this vulnerability type?
        (From historical statistics)
        """
        
        base_rates = {
            'SQL Injection': 0.15,          # ~15% of web apps
            'Command Injection': 0.08,     # ~8%
            'Logic Bug': 0.25,              # ~25%
            'TOCTOU': 0.05,                 # ~5%
            'Race Condition': 0.03,        # ~3%
            'XXE': 0.04,                    # ~4%
            'CORS Misconfiguration': 0.12, # ~12%
            'Hardcoded Secret': 0.20,      # ~20%
            'Type Confusion': 0.06,         # ~6%
        }
        
        return base_rates.get(vulnerability_type, 0.10)  # Default 10%

```

### Bayesian Update Example

```
SCENARIO: Finding with initial confidence 60%, new evidence arrives

PRIOR:
├─ Confidence in vulnerability: 60%
└─ Type: SQL Injection

NEW EVIDENCE:
├─ Additional detector finds entry point
├─ Data flow tracking confirms path to database
└─ Similar pattern found in codebase

BAYESIAN CALCULATION:
├─ Prior probability P(V): 0.60
├─ P(Evidence | Vulnerability): 0.85 (strong support)
├─ P(Evidence | Not Vulnerability): 0.20 (weak contradiction)
├─ Base rate for SQL injection: 0.15
├─ P(Evidence): 0.85 × 0.60 + 0.20 × 0.40 = 0.59
├─ Posterior: (0.85 × 0.60) / 0.59 = 0.864 = 86.4%

RESULT:
├─ Prior Confidence: 60.0%
├─ New Evidence: Entry point + Data flow + Similar pattern
├─ Posterior Confidence: 86.4%
└─ Action: ESCALATE TO TIER 2 (verification queue)
```

---

## ORM Models

### Low-Confidence Finding Model

```python
from sqlalchemy import Column, String, Integer, Float, Boolean, Text, JSON, ForeignKey, DateTime
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
import uuid

from itl_braincell_sdk.core.models import Base, TimestampMixin

class LowConfidenceFinding(Base, TimestampMixin):
    """Uncertain finding awaiting verification or escalation"""
    __tablename__ = "low_confidence_findings"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # --- Basic Information ---
    repo_owner = Column(String, nullable=False)
    repo_name = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    
    # --- Finding Details ---
    finding_type = Column(String, nullable=False)  # SQL Injection, Logic Bug, etc.
    description = Column(Text)
    code_snippet = Column(Text)
    line_number = Column(Integer)
    
    # --- Confidence Metrics ---
    initial_confidence = Column(Float, nullable=False)  # 0.0-1.0
    current_confidence = Column(Float, nullable=False)
    confidence_percentage = Column(String)  # "45.2%"
    
    # --- Ensemble Voting ---
    detectors_voting = Column(JSON)  # ["StaticAnalysis", "ASTAnalysis", "ML"]
    vote_count = Column(Integer)  # How many detectors agree
    ensemble_strength = Column(String)  # STRONG, MODERATE, WEAK, SUSPICIOUS
    
    # --- Evidence ---
    signals = Column(JSON)  # Raw signals from each detector
    evidence_chain = Column(JSON)  # Entry point, flow, sink analysis
    data_flow_verified = Column(Boolean, default=False)
    
    # --- Scoring Breakdown ---
    detector_agreement_score = Column(Float)
    pattern_specificity_score = Column(Float)
    evidence_chain_score = Column(Float)
    reliability_score = Column(Float)
    
    # --- Clustering ---
    cluster_id = Column(String, nullable=True)
    cluster_size = Column(Integer, nullable=True)  # How many similar findings?
    cluster_aggregate_confidence = Column(Float, nullable=True)
    similar_findings_count = Column(Integer, default=0)
    
    # --- Pattern History ---
    pattern_historical_accuracy = Column(Float, nullable=True)  # 0.0-1.0
    false_positive_rate = Column(Float, nullable=True)
    base_rate = Column(Float, nullable=True)  # How common is this type?
    
    # --- Bayesian Update ---
    prior_confidence = Column(Float, nullable=True)
    posterior_confidence = Column(Float, nullable=True)
    bayesian_evidence = Column(JSON, nullable=True)  # Evidence that updated confidence
    
    # --- Decay ---
    original_created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    days_since_creation = Column(Integer, default=0)
    decay_applied = Column(Float, default=0.0)  # Total decay amount
    
    # --- Status ---
    status = Column(String, default='in_pool')  # in_pool, queued_review, escalated, resolved, archived
    tier = Column(String, default='tier4')  # tier1-4
    
    # --- Verification ---
    verified = Column(Boolean, default=False)
    verification_result = Column(String, nullable=True)  # true_positive, false_positive
    verifier_name = Column(String, nullable=True)
    verifier_notes = Column(Text, nullable=True)
    verification_date = Column(DateTime, nullable=True)
    confidence_in_verdict = Column(Float, nullable=True)  # Verifier confidence


class ConfidenceUpdate(Base, TimestampMixin):
    """History of confidence changes"""
    __tablename__ = "confidence_updates"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id = Column(ForeignKey("low_confidence_findings.id"))
    
    # Old and new confidence
    previous_confidence = Column(Float)
    new_confidence = Column(Float)
    change_amount = Column(Float)  # new - previous
    
    # Reason for change
    reason = Column(String)  # "decay", "bayesian_update", "cluster_escalation", "verification"
    context = Column(JSON)
    
    # New signals
    new_evidence = Column(JSON, nullable=True)


class ConfidenceFactor(Base, TimestampMixin):
    """Breakdown of confidence calculation"""
    __tablename__ = "confidence_factors"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id = Column(ForeignKey("low_confidence_findings.id"))
    
    # Factors and weights
    detector_agreement = Column(Float)  # Factor value
    detector_agreement_weight = Column(Float)  # 0.40
    
    pattern_specificity = Column(Float)
    pattern_specificity_weight = Column(Float)  # 0.25
    
    evidence_chain = Column(Float)
    evidence_chain_weight = Column(Float)  # 0.20
    
    reliability = Column(Float)
    reliability_weight = Column(Float)  # 0.15
    
    # Total
    total_confidence = Column(Float)
    meets_threshold = Column(Boolean)  # confidence >= 0.60


class PatternStatistic(Base, TimestampMixin):
    """Historical accuracy of each pattern type"""
    __tablename__ = "pattern_statistics"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Pattern
    pattern_type = Column(String, nullable=False, unique=True)  # SQL Injection, etc.
    
    # Statistics
    total_findings = Column(Integer, default=0)
    verified_true_positives = Column(Integer, default=0)
    false_positives = Column(Integer, default=0)
    
    # Calculated metrics
    accuracy = Column(Float)  # true / total
    true_positive_rate = Column(Float)
    false_positive_rate = Column(Float)
    
    # Recommendation
    reliability_status = Column(String)  # HIGHLY_RELIABLE, RELIABLE, MODERATE, UNRELIABLE
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
```

---

## Service Implementation

### Low-Confidence Finding Service

```python
# FILE: ITL.Braincell.SDK/src/itl_braincell_sdk/services/low_confidence_service.py

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from typing import Optional, List
import asyncio
import math

class LowConfidenceService:
    """Manage low-confidence findings through verification pipeline"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def process_finding(self, vulnerability: dict) -> dict:
        """Process a finding through confidence routing"""
        
        # Step 1: Calculate confidence with all factors
        confidence_result = await self._calculate_confidence(vulnerability)
        vulnerability['confidence'] = confidence_result['confidence']
        vulnerability['confidence_breakdown'] = confidence_result['breakdown']
        
        # Step 2: Apply pattern-based adjustments
        adjusted = await self._apply_pattern_adjustment(vulnerability)
        vulnerability['confidence'] = adjusted
        
        # Step 3: Route based on confidence
        action = await self._route_by_confidence(vulnerability)
        
        return {
            'finding': vulnerability,
            'action': action,
            'confidence': adjusted
        }
    
    async def _calculate_confidence(self, vuln: dict) -> dict:
        """Calculate confidence with factor breakdown"""
        
        factors = {}
        weights = {
            'detector_agreement': 0.40,
            'pattern_specificity': 0.25,
            'evidence_chain': 0.20,
            'reliability': 0.15
        }
        
        # Factor 1: Detector agreement
        detector_count = len(vuln.get('detectors_voting', []))
        detector_score = (detector_count / 8) * weights['detector_agreement']
        factors['detector_agreement'] = detector_score
        
        # Factor 2: Pattern specificity
        pattern_specificity = await self._assess_pattern_specificity(vuln)
        factors['pattern_specificity'] = pattern_specificity * weights['pattern_specificity']
        
        # Factor 3: Evidence chain
        evidence_score = await self._check_evidence_chain(vuln)
        factors['evidence_chain'] = evidence_score * weights['evidence_chain']
        
        # Factor 4: Pattern reliability
        pattern_type = vuln['type']
        stats = await self._get_pattern_stats(pattern_type)
        reliability = stats.get('accuracy', 0.5) if stats else 0.5
        factors['reliability'] = reliability * weights['reliability']
        
        total = sum(factors.values())
        
        return {
            'confidence': total,
            'breakdown': factors
        }
    
    async def cluster_low_confidence(self, findings: List[dict]):
        """Cluster similar low-confidence findings"""
        
        clusterer = LowConfidenceClusterer(self.db)
        await clusterer.cluster_findings(findings)
    
    async def apply_confidence_decay(self, finding_id: str):
        """Apply time decay to stale findings"""
        
        finding = await self.db.get(LowConfidenceFinding, finding_id)
        
        days_old = (datetime.now() - finding.original_created_at).days
        decay = (days_old / 30) * 0.01  # 1% per month
        
        decayed = max(0.0, min(1.0, finding.current_confidence - decay))
        
        await self.db.execute(
            update(LowConfidenceFinding)
            .where(LowConfidenceFinding.id == finding_id)
            .values(
                current_confidence=decayed,
                decay_applied=decay
            )
        )
        await self.db.commit()
    
    async def bayesian_update(self, finding_id: str, new_evidence: dict) -> float:
        """Update confidence using Bayes' theorem"""
        
        finding = await self.db.get(LowConfidenceFinding, finding_id)
        
        updater = BayesianConfidenceUpdater()
        posterior = updater.update_with_new_evidence(
            finding.current_confidence,
            new_evidence
        )
        
        # Record update
        update_record = ConfidenceUpdate(
            finding_id=finding_id,
            previous_confidence=finding.current_confidence,
            new_confidence=posterior,
            change_amount=posterior - finding.current_confidence,
            reason="bayesian_update",
            new_evidence=new_evidence
        )
        self.db.add(update_record)
        
        # Update finding
        await self.db.execute(
            update(LowConfidenceFinding)
            .where(LowConfidenceFinding.id == finding_id)
            .values(
                current_confidence=posterior,
                posterior_confidence=posterior
            )
        )
        await self.db.commit()
        
        return posterior
```

---

## Complete Workflow

### End-to-End Low-Confidence Processing

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. FINDING DETECTED                                             │
│   • One or more detectors flag potential vulnerability          │
│   • Confidence: 35-70% (too uncertain for automatic action)     │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 2. ENSEMBLE VOTING                                              │
│   • All 8 detectors run on code                                │
│   • Count agreement: 3/8, 4/8, 5/8 detectors agree            │
│   • Calculate ensemble confidence                              │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 3. MULTI-FACTOR SCORING                                         │
│   • Detector agreement: 50% (4/8 × 0.40 = 0.20)              │
│   • Pattern specificity: 40% (0.40 × 0.25 = 0.10)            │
│   • Evidence chain: 70% (0.70 × 0.20 = 0.14)                 │
│   • Reliability: 60% (0.60 × 0.15 = 0.09)                    │
│   • Total: 53% confidence                                      │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 4. CONFIDENCE-BASED ROUTING                                    │
│   • Confidence 53% → TIER 3 (Possible vulnerabilities)        │
│   • Action: Save to low-confidence pool, attempt clustering    │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 5. CLUSTERING                                                   │
│   • Search for similar findings in same file                   │
│   • Same type + same file + confidence 40-60%                 │
│   • Cluster size: 7 findings found                             │
│   • Average confidence: 48%                                    │
│   • Cluster bonus: log(7+1)/10 = 0.095                        │
│   • Aggregate confidence: 48% + 9.5% = 57.5%                 │
│   • Still below escalation threshold (70%)                     │
│   • Decision: Keep monitoring                                  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
         ┌────────────────────────────────────┐
         │ Wait: Continue collecting signals  │
         │       for 1-2 weeks                │
         │                                    │
         │ Meanwhile: Update pattern stats    │
         │           Decay old findings       │
         │           Prepare review queue     │
         └────────────────────────────────────┘
                              ↓
      (Additional evidence emerges or cluster grows)
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 6. ESCALATION TRIGGER (One of these)                           │
│   • Cluster now 12 findings (threshold: 5+ met)               │
│   • New detector adds entry point verification               │
│   • Code review finds obfuscation in file                    │
│   • Research paper links to attack pattern                   │
│                                                               │
│   → Aggregate confidence now 72% (above 70% threshold)       │
│   → ESCALATE TO TIER 2                                       │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 7. VERIFICATION QUEUE                                           │
│   • Add to priority queue for human review                    │
│   • Priority: 0.65 (medium-high)                              │
│   • Estimated review: 5 minutes                                │
│   • Provide context: Function code, similar findings          │
│   • Request verdict: YES/NO/MAYBE                              │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 8. HUMAN VERIFICATION                                           │
│   • Analyst reviews finding in ~5 minutes                      │
│   • Reads vulnerable code                                      │
│   • Checks data flow                                           │
│   • Renders verdict: YES (true positive)                       │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 9. PATTERN LEARNING                                             │
│   • Record: Logic bypass pattern verified true                │
│   • Update pattern statistics:                                │
│     - Total: 12 → 13                                          │
│     - True positives: 10 → 11                                 │
│     - Accuracy: 83% → 85%                                     │
│   • This pattern is now MORE RELIABLE                         │
│   • Future similar findings get higher confidence             │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 10. ESCALATION TO TIER 1                                       │
│   • Verified finding → TIER 1 (High confidence)               │
│   • Actions:                                                   │
│     - Flag as vulnerability                                  │
│     - Generate POC                                           │
│     - Create GitHub issue                                    │
│     - Notify security team                                   │
│     - Plan exploitation/remediation                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Success Metrics

### Confidence Framework Effectiveness

| Metric | Target | Impact |
|--------|--------|--------|
| **False Positive Rate** | <10% | Reduces alert fatigue |
| **Cluster Accuracy** | >75% | Aggregation works well |
| **Pattern Reliability** | >80% | Historical learning is accurate |
| **Escalation Rate** | 15-25% | Right findings promoted |
| **Verification Speed** | <8 min/finding | Efficient human review |
| **Time to Escalate** | 1-2 weeks | Findings escalate when patterns emerge |

### Tier Distribution (Target)

| Tier | Percentage | Action |
|------|-----------|--------|
| Tier 1 (>90%) | 5-10% | Immediate action |
| Tier 2 (70-90%) | 10-15% | Verification queue |
| Tier 3 (50-70%) | 20-30% | Clustering pool |
| Tier 4 (<50%) | 45-65% | Archive/learning |

### Pattern Learning Milestones

- **Week 1**: Establish baseline statistics for 20+ patterns
- **Week 4**: Identify most reliable patterns (>85% accuracy)
- **Week 8**: Identify unreliable patterns (<30% accuracy)
- **Week 12**: Begin adjusting detector weights based on accuracy

---

## Implementation Priority

### Phase 1: Foundation (Week 1)
- [ ] Implement ensemble voting (8 detectors)
- [ ] Build confidence scoring framework
- [ ] Create ORM models
- [ ] Deploy basic routing

### Phase 2: Clustering (Week 2)
- [ ] Implement clustering algorithm
- [ ] Build pattern database
- [ ] Add cluster escalation logic
- [ ] Create cluster monitoring

### Phase 3: Verification (Week 3)
- [ ] Build verification queue
- [ ] Implement priority scoring
- [ ] Create reviewer UI/prompts
- [ ] Track verification feedback

### Phase 4: Learning (Week 4)
- [ ] Pattern statistics tracking
- [ ] Confidence adjustment based on history
- [ ] Bayesian updates
- [ ] Confidence decay

### Phase 5: Optimization (Week 5+)
- [ ] Analyze performance metrics
- [ ] Adjust weights based on accuracy
- [ ] Fine-tune thresholds
- [ ] Continuous learning loop

---

## Next Steps

Create the following:
1. **LowConfidenceFinding cell** with all ORM models
2. **LowConfidenceService** with processing logic
3. **Ensemble detector** with 8 detection methods
4. **Cluster analyzer** with aggregation logic
5. **Verification queue UI** for human review
6. **Pattern learning system** with statistics tracking
7. **Integration** with existing security analysis workflow
