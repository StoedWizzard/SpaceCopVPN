"""Tests for fragmentation: 20 KB splitting, shuffling, and reassembly."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spacecop.fragmentation import Fragment, Fragmenter, Reassembler, ReassemblyError
from spacecop.protocol import constants as c


class TestFragmenter(unittest.TestCase):
    def test_fragment_size_is_20kb(self):
        self.assertEqual(c.FRAGMENT_SIZE, 20 * 1024)

    def test_split_counts(self):
        f = Fragmenter()
        payload = os.urandom(50 * 1024)  # 50 KB -> 3 fragments (20+20+10)
        frags = f.fragment(payload, shuffle=False)
        self.assertEqual(len(frags), 3)
        self.assertEqual(len(frags[0].payload), 20 * 1024)
        self.assertEqual(len(frags[1].payload), 20 * 1024)
        self.assertEqual(len(frags[2].payload), 10 * 1024)
        self.assertTrue(all(fr.count == 3 for fr in frags))
        self.assertEqual([fr.index for fr in frags], [0, 1, 2])

    def test_empty_payload_makes_one_fragment(self):
        f = Fragmenter()
        frags = f.fragment(b"")
        self.assertEqual(len(frags), 1)
        self.assertEqual(frags[0].payload, b"")
        self.assertEqual(frags[0].count, 1)

    def test_exact_multiple(self):
        f = Fragmenter()
        payload = os.urandom(40 * 1024)  # exactly 2 fragments
        frags = f.fragment(payload, shuffle=False)
        self.assertEqual(len(frags), 2)

    def test_shuffle_changes_order(self):
        f = Fragmenter()
        payload = os.urandom(200 * 1024)  # 10 fragments
        # With 10 fragments, the probability the shuffle equals identity order
        # across several tries is negligible.
        saw_shuffle = False
        for _ in range(10):
            frags = f.fragment(payload, group_id=1, shuffle=True)
            if [fr.index for fr in frags] != list(range(10)):
                saw_shuffle = True
                break
        self.assertTrue(saw_shuffle, "shuffle never changed the order")

    def test_fragment_encode_decode(self):
        frag = Fragment(group_id=0xDEADBEEF, count=5, index=3, payload=b"chunk")
        decoded = Fragment.decode(frag.encode())
        self.assertEqual(decoded.group_id, 0xDEADBEEF)
        self.assertEqual(decoded.count, 5)
        self.assertEqual(decoded.index, 3)
        self.assertEqual(decoded.payload, b"chunk")


class TestReassembler(unittest.TestCase):
    def test_reassemble_in_order(self):
        f = Fragmenter()
        r = Reassembler()
        payload = os.urandom(45 * 1024)
        frags = f.fragment(payload, shuffle=False)
        result = None
        for fr in frags:
            result = r.add(fr)
        self.assertEqual(result, payload)

    def test_reassemble_shuffled(self):
        f = Fragmenter()
        r = Reassembler()
        payload = os.urandom(123 * 1024)
        frags = f.fragment(payload, shuffle=True)
        result = None
        for fr in frags:
            got = r.add(fr)
            if got is not None:
                result = got
        self.assertEqual(result, payload)

    def test_duplicates_ignored(self):
        f = Fragmenter()
        r = Reassembler()
        payload = os.urandom(30 * 1024)
        frags = f.fragment(payload, shuffle=False)
        # Feed the first fragment several times before the rest.
        self.assertIsNone(r.add(frags[0]))
        self.assertIsNone(r.add(frags[0]))
        self.assertIsNone(r.add(frags[0]))
        result = r.add(frags[1])
        self.assertEqual(result, payload)

    def test_completion_only_on_last(self):
        f = Fragmenter()
        r = Reassembler()
        payload = os.urandom(60 * 1024)  # 3 fragments
        frags = f.fragment(payload, shuffle=False)
        self.assertIsNone(r.add(frags[2]))
        self.assertIsNone(r.add(frags[0]))
        self.assertEqual(r.add(frags[1]), payload)

    def test_missing_indices(self):
        f = Fragmenter()
        r = Reassembler()
        payload = os.urandom(80 * 1024)  # 4 fragments
        frags = f.fragment(payload, group_id=7, shuffle=False)
        r.add(frags[0])
        r.add(frags[2])
        self.assertEqual(sorted(r.missing_indices(7)), [1, 3])

    def test_bytes_roundtrip(self):
        f = Fragmenter()
        r = Reassembler()
        payload = b"the quick brown fox " * 5000
        result = None
        for raw in f.fragment_encoded(payload, shuffle=True):
            got = r.add_bytes(raw)
            if got is not None:
                result = got
        self.assertEqual(result, payload)

    def test_inconsistent_count_rejected(self):
        r = Reassembler()
        r.add(Fragment(group_id=1, count=3, index=0, payload=b"a"))
        with self.assertRaises(ReassemblyError):
            r.add(Fragment(group_id=1, count=4, index=1, payload=b"b"))

    def test_bad_index_rejected(self):
        r = Reassembler()
        with self.assertRaises(ReassemblyError):
            r.add(Fragment(group_id=1, count=2, index=5, payload=b"x"))

    def test_two_interleaved_groups(self):
        f = Fragmenter()
        r = Reassembler()
        p1 = os.urandom(30 * 1024)
        p2 = os.urandom(25 * 1024)
        g1 = f.fragment(p1, group_id=100, shuffle=False)
        g2 = f.fragment(p2, group_id=200, shuffle=False)
        results = []
        # Interleave the two groups.
        for a, b in zip(g1, g2):
            got = r.add(a)
            if got is not None:
                results.append(got)
            got = r.add(b)
            if got is not None:
                results.append(got)
        self.assertIn(p1, results)
        self.assertIn(p2, results)

    def test_max_groups_eviction(self):
        r = Reassembler(max_groups=2)
        # Open three partial groups; the oldest should be evicted.
        r.add(Fragment(group_id=1, count=2, index=0, payload=b"a"))
        r.add(Fragment(group_id=2, count=2, index=0, payload=b"b"))
        r.add(Fragment(group_id=3, count=2, index=0, payload=b"c"))
        self.assertLessEqual(r.pending_groups(), 2)


class TestFragmentationEndToEnd(unittest.TestCase):
    """Fragment -> encrypt each fragment -> shuffle -> decrypt -> reassemble."""

    def test_encrypted_fragment_pipeline(self):
        from spacecop.protocol import (
            ClientHandshake, NodeHandshake, NodeIdentity, framing,
        )
        node_id = NodeIdentity.generate()
        client = ClientHandshake(node_id.x_public)
        _, init_body = framing.decode_frame(client.build_init())
        node = NodeHandshake(node_id)
        resp_frame, node_session = node.handle_init(init_body)
        _, resp_body = framing.decode_frame(resp_frame)
        client_session = client.consume_response(resp_body)

        payload = os.urandom(100 * 1024 + 137)  # not a fragment multiple
        f = Fragmenter()
        # Client seals each fragment independently and sends them shuffled.
        sealed_records = [client_session.seal(raw)
                          for raw in f.fragment_encoded(payload, shuffle=True)]

        r = Reassembler()
        result = None
        for sealed in sealed_records:
            fragment_bytes = node_session.open(sealed)
            got = r.add_bytes(fragment_bytes)
            if got is not None:
                result = got
        self.assertEqual(result, payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
