from threatintel.extractor import ThreatIntelExtractor

def test_extract_and_defang_url():
    raw = "http://malicious.example.com"
    defanged = ThreatIntelExtractor.defang(raw)
    assert defanged == "hxxp[://]malicious[.]example[.]com"
    assert ThreatIntelExtractor.refang(defanged) == raw

def test_sha256_extraction():
    text = "Malware hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 detected"
    extractor = ThreatIntelExtractor()
    iocs = extractor.extract_iocs(text)
    assert len(iocs["sha256"]) == 1
    assert iocs["sha256"][0] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
