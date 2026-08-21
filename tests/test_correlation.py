import copy
import unittest

from scanner.correlation import correlate_report


def report(observations=None, neighbors=None):
    return {"scan_id":"scan_x","assets":[{"asset_id":"a","addresses":[{"address":"192.168.1.2"}]},{"asset_id":"b","addresses":[{"address":"192.168.1.3"}]}],"observations":observations or [],"neighbor_observations":neighbors or [],"name_observations":[]}


class CorrelationTests(unittest.TestCase):
    def test_identical_tls_hash_creates_candidate_not_identity(self):
        value = report([{"asset_id":"b","observation_id":"o2","tls":{"certificate_sha256":"abc"}},{"asset_id":"a","observation_id":"o1","tls":{"certificate_sha256":"abc"}}])
        relations, execution = correlate_report(value)
        self.assertEqual(relations[0]["members"], ["a","b"]); self.assertEqual(relations[0]["confidence"], "medium")
        self.assertFalse(relations[0]["physical_device_asserted"]); self.assertEqual(execution["relations_observed"], 1)

    def test_ptr_and_service_only_do_not_cluster(self):
        value = report([{"asset_id":"a","observation_id":"o1","service":{"name":"http"}},{"asset_id":"b","observation_id":"o2","service":{"name":"http"}}])
        value["name_observations"] = [{"address":"192.168.1.2","names":["same"]},{"address":"192.168.1.3","names":["same"]}]
        self.assertEqual(correlate_report(value)[0], [])

    def test_neighbor_hash_requires_same_context(self):
        neighbors = [{"address":"192.168.1.2","neighbor_observation_id":"n1","link_layer_sha256":"h","network_context":"linux","interface":"eth0"},{"address":"192.168.1.3","neighbor_observation_id":"n2","link_layer_sha256":"h","network_context":"linux","interface":"eth0"}]
        self.assertEqual(len(correlate_report(report(neighbors=neighbors))[0]), 1)
        neighbors[1]["interface"] = "eth1"
        self.assertEqual(correlate_report(report(neighbors=neighbors))[0], [])

    def test_http_hash_low_relation_and_contradiction(self):
        observations = [{"asset_id":"a","observation_id":"o1","http":{"body_prefix_sha256":"same"},"tls":{"certificate_sha256":"cert"}},{"asset_id":"b","observation_id":"o2","http":{"body_prefix_sha256":"same"},"tls":{"certificate_sha256":"cert"}}]
        neighbors = [{"address":"192.168.1.2","neighbor_observation_id":"n1","link_layer_sha256":"one","network_context":"linux","interface":"eth0"},{"address":"192.168.1.3","neighbor_observation_id":"n2","link_layer_sha256":"two","network_context":"linux","interface":"eth0"}]
        relations, _ = correlate_report(report(observations, neighbors))
        self.assertEqual({item["confidence"] for item in relations}, {"low","medium"})
        self.assertTrue(next(item for item in relations if item["confidence"] == "medium")["contradictions"])

    def test_order_ids_limits_truncation_and_no_mutation(self):
        observations = [{"asset_id":"a","observation_id":"o1","tls":{"certificate_sha256":"x"}},{"asset_id":"b","observation_id":"o2","tls":{"certificate_sha256":"x"}}]
        value = report(observations); original = copy.deepcopy(value)
        first = correlate_report(value); second = correlate_report(report(list(reversed(observations))))
        self.assertEqual(first, second); self.assertEqual(value, original)
        relations, execution = correlate_report(value, max_signals=1)
        self.assertEqual(relations, []); self.assertTrue(execution["truncated"])
