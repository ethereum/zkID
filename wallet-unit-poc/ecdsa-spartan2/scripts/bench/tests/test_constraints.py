import json
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import constraints as c

PRIME = (1 << 256) - 1  # value is irrelevant to the parser


def r1cs_bytes(n_wires, n_pub_out, n_pub_in, n_prv_in, n_labels, n_cons, order=(1, 2, 3)):
    header = struct.pack("<I", 32) + PRIME.to_bytes(32, "little")
    header += struct.pack("<IIIIQI", n_wires, n_pub_out, n_pub_in, n_prv_in, n_labels, n_cons)
    bodies = {1: header, 2: b"\x00" * 12, 3: b"\x00" * 8}
    out = b"r1cs" + struct.pack("<II", 1, len(order))
    for t in order:
        out += struct.pack("<IQ", t, len(bodies[t])) + bodies[t]
    return out


class ParseHeader(unittest.TestCase):
    def write(self, data):
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".r1cs")
        f.write(data)
        f.close()
        self.addCleanup(os.unlink, f.name)
        return f.name

    def test_reads_all_header_fields(self):
        h = c.parse_header(self.write(r1cs_bytes(100, 3, 7, 20, 99, 55)))
        self.assertEqual(h["constraints"], 55)
        self.assertEqual(h["wires"], 100)
        self.assertEqual(h["outputs"], 3)
        self.assertEqual(h["public_inputs"], 7)
        self.assertEqual(h["private_inputs"], 20)
        self.assertEqual(h["labels"], 99)

    def test_header_not_first_section(self):
        h = c.parse_header(self.write(r1cs_bytes(9, 1, 2, 3, 4, 5, order=(3, 2, 1))))
        self.assertEqual(h["constraints"], 5)

    def test_rejects_bad_magic(self):
        with self.assertRaises(ValueError):
            c.parse_header(self.write(b"nope" + b"\x00" * 40))


class Padding(unittest.TestCase):
    def test_pad_to_width_matches_spartan2(self):
        self.assertEqual(c.pad_to_width(1024, 0), 0)
        self.assertEqual(c.pad_to_width(1024, 1), 1024)
        self.assertEqual(c.pad_to_width(1024, 1024), 1024)
        self.assertEqual(c.pad_to_width(1024, 1025), 2048)

    def test_constraints_pad_to_next_power_of_two(self):
        s = c.padded_shape(num_cons=1_000_000, num_shared=100, num_aux=1_500_000, num_public=10)
        self.assertEqual(s["cons_padded"], 1 << 20)

    def test_exact_power_of_two_is_unchanged(self):
        s = c.padded_shape(num_cons=1 << 20, num_shared=0, num_aux=1 << 20, num_public=1)
        self.assertEqual(s["cons_padded"], 1 << 20)

    def test_vars_pad_to_power_of_two_of_width_multiples(self):
        s = c.padded_shape(num_cons=10, num_shared=100, num_aux=3000, num_public=5)
        # shared 100 -> 1024, rest 2900 -> 3072, sum 4096 is already a power of two
        self.assertEqual((s["shared_padded"], s["rest_padded"], s["vars_padded"]), (1024, 3072, 4096))

    def test_vars_round_up_when_sum_is_not_power_of_two(self):
        s = c.padded_shape(num_cons=10, num_shared=1100, num_aux=3000, num_public=5)
        # shared 2048 + rest 2048 -> 4096
        self.assertEqual(s["vars_padded"], 4096)
        s = c.padded_shape(num_cons=10, num_shared=2000, num_aux=7000, num_public=5)
        # shared 2048 + rest 5120 = 7168 -> rest grows to 6144, total 8192
        self.assertEqual(s["vars_padded"], 8192)

    def test_size_class_is_log2_of_padded_constraints(self):
        self.assertEqual(c.padded_shape(1 << 20, 0, 10, 1)["cons_log2"], 20)
        self.assertEqual(c.padded_shape((1 << 20) + 1, 0, 10, 1)["cons_log2"], 21)


class Rows(unittest.TestCase):
    def test_row_has_schema_fields(self):
        hdr = dict(constraints=5, wires=9, public_inputs=2, private_inputs=3, outputs=1, labels=4)
        row = c.constraints_row("combined", "show", 8, 20, None, hdr, "ab" * 32)
        self.assertEqual(row["kind"], "CONSTRAINTS")
        for k in ("config", "circuit", "d_iss", "d_rev", "jwt_size", "constraints", "wires",
                  "public_inputs", "private_inputs", "outputs", "labels", "r1cs_sha256"):
            self.assertIn(k, row)

    def test_depths_come_from_circuits_json_params(self):
        cj = {"show": {"template": "Show", "params": [2, 2, 8, 64, 8, 10]},
              "jwt_2k": {"template": "JWT", "params": [2048, 2000, 4, 50, 128]}}
        self.assertEqual(c.depths_for("combined", cj, "show"), (8, 10))
        self.assertEqual(c.depths_for("combined", cj, "jwt_2k"), (None, None))
        self.assertEqual(c.depths_for("issuer", {"show": {"template": "Show", "params": [2, 2, 8, 64, 8]}}, "show"), (8, None))
        self.assertEqual(c.depths_for("revocation", {"show": {"template": "Show", "params": [2, 2, 8, 64, 10]}}, "show"), (None, 10))
        self.assertEqual(c.depths_for("main", {"show": {"template": "Show", "params": [2, 2, 8, 64]}}, "show"), (None, None))

    def test_jwt_size_from_circuit_name(self):
        self.assertEqual(c.jwt_size_of("jwt_2k"), "2k")
        self.assertIsNone(c.jwt_size_of("show"))


class LinearFit(unittest.TestCase):
    def test_exact_linear(self):
        slope, intercept, exact = c.linear_fit([(0, 10), (4, 18), (8, 26)])
        self.assertEqual((slope, intercept, exact), (2, 10, True))

    def test_not_linear(self):
        _, _, exact = c.linear_fit([(0, 10), (4, 18), (8, 27)])
        self.assertFalse(exact)


if __name__ == "__main__":
    unittest.main()
