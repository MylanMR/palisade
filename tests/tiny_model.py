"""Write a tiny llama-architecture GGUF with a Gemma-style chat template.

It has no knowledge and always answers " the the the ...", which is the point: it lets the harness be
tested against the real llama-server binary (its tokenizer, its API key handling, its
flags) in seconds, with nothing downloaded but the pinned server build.

    python tests/tiny_model.py OUT.gguf
"""
import sys

import numpy as np
import gguf


def write(out: str) -> int:
    w = gguf.GGUFWriter(out, "llama")
    d, ff, ctx = 16, 32, 8192
    tokens, scores, types = [], [], []

    def add(t, s, ty):
        tokens.append(t.encode()); scores.append(float(s)); types.append(ty)

    add("<unk>", 0, gguf.TokenType.UNKNOWN)
    add("<bos>", 0, gguf.TokenType.CONTROL)
    add("<eos>", 0, gguf.TokenType.CONTROL)
    add("<start_of_turn>", 0, gguf.TokenType.CONTROL)
    add("<end_of_turn>", 0, gguf.TokenType.CONTROL)
    add("<private_ctl>", 0, gguf.TokenType.CONTROL)     # a token no pattern list knows
    for b in range(256):
        add(f"<0x{b:02X}>", 0, gguf.TokenType.BYTE)
    for i, p in enumerate(["▁", "▁the", "▁a", "e", "t", "a", "o", "user", "model", "\n"]):
        add(p, -float(i + 1), gguf.TokenType.NORMAL)

    w.add_name("palisade-tiny-test")
    w.add_context_length(ctx)
    w.add_embedding_length(d)
    w.add_block_count(1)
    w.add_feed_forward_length(ff)
    w.add_head_count(2)
    w.add_head_count_kv(2)
    w.add_rope_dimension_count(d // 2)
    w.add_layer_norm_rms_eps(1e-5)
    w.add_file_type(gguf.LlamaFileType.ALL_F32)
    w.add_tokenizer_model("llama")
    w.add_token_list(tokens)
    w.add_token_scores(scores)
    w.add_token_types(types)
    w.add_bos_token_id(1)
    w.add_eos_token_id(2)
    w.add_unk_token_id(0)
    w.add_add_bos_token(True)
    w.add_chat_template(
        "{{ bos_token }}{% for m in messages %}<start_of_turn>{{ 'model' if m['role'] == 'assistant' else m['role'] }}\n"
        "{{ m['content'] }}<end_of_turn>\n{% endfor %}{% if add_generation_prompt %}<start_of_turn>model\n{% endif %}")

    # Deterministic, readable output: every token embeds to the same vector, the attention
    # and feed-forward weights are zero, and only the " the" row of the output matrix
    # points along that vector, so the model always answers " the the the ...".
    V = len(tokens)
    e = np.zeros(d, np.float32); e[0] = 1.0
    w.add_tensor("token_embd.weight", np.tile(e, (V, 1)))
    w.add_tensor("output_norm.weight", np.ones(d, np.float32))
    out_w = np.zeros((V, d), np.float32)
    out_w[tokens.index("\u2581the".encode())] = e * 4.0     # " the"
    w.add_tensor("output.weight", out_w)
    w.add_tensor("blk.0.attn_norm.weight", np.ones(d, np.float32))
    w.add_tensor("blk.0.ffn_norm.weight", np.ones(d, np.float32))
    for n in ("attn_q", "attn_k", "attn_v", "attn_output"):
        w.add_tensor(f"blk.0.{n}.weight", np.zeros((d, d), np.float32))
    w.add_tensor("blk.0.ffn_gate.weight", np.zeros((ff, d), np.float32))
    w.add_tensor("blk.0.ffn_up.weight", np.zeros((ff, d), np.float32))
    w.add_tensor("blk.0.ffn_down.weight", np.zeros((d, ff), np.float32))
    w.write_header_to_file(); w.write_kv_data_to_file(); w.write_tensors_to_file(); w.close()
    return V


if __name__ == "__main__":
    print(write(sys.argv[1]))
