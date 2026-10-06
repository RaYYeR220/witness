// @vitest-environment jsdom
import { flushPromises, mount } from "@vue/test-utils";
import { afterEach, describe, expect, it, vi } from "vitest";

import { sealed } from "@/test/vectors";

import MessageBody from "./MessageBody.vue";

/** A sealed witness/v1 envelope as the explorer returns it: no body, the JWE in `enc`. */
const envelope = {
  w: 1,
  tag: "trust.score",
  iss: "did:iota:testnet:0x5e1f",
  kid: "did:iota:testnet:0x5e1f#sig-1",
  seq: 7,
  iat: 1791283579000,
  nonce: "AAAAAAAAAAAAAAAAAAAAAA",
  att: { mode: "producer" },
  enc: sealed.jwe,
  bix: ["PaITfGG18DlzZ7Hde2GcHN2ty0J4yxp1muRSJ-vL14k"],
  sig: "A".repeat(86),
};

async function pick(w: ReturnType<typeof mount>, content: unknown) {
  const input = w.find('input[type="file"]');
  const file = new File([JSON.stringify(content)], "kex-1.jwk.json", { type: "application/json" });
  Object.defineProperty(input.element, "files", { value: [file], configurable: true });
  await input.trigger("change");
  // decryption is async WebCrypto work: let it finish
  for (let i = 0; i < 20 && w.find(".btn").exists() && w.find(".btn").text().startsWith("Decrypting"); i++) {
    await new Promise((r) => setTimeout(r, 10));
  }
  await flushPromises();
  await new Promise((r) => setTimeout(r, 30));
  await flushPromises();
}

afterEach(() => vi.restoreAllMocks());

describe("MessageBody, sealed", () => {
  it("shows a ciphertext badge and no plaintext without a key", () => {
    const w = mount(MessageBody, { props: { json: envelope } });
    expect(w.find('.badge[data-k="cipher"]').text()).toBe("Ciphertext");
    expect(w.find("[data-plain]").exists()).toBe(false);
    expect(w.text()).not.toContain("0.745");
    expect(w.findAll(".rcpt li").map((li) => li.attributes("title"))).toEqual(["a#k", "b#k"]);
  });

  it("decrypts with a local key file in the browser, without any network call", async () => {
    const fetchSpy = vi.fn(() => Promise.reject(new Error("no network in this test")));
    vi.stubGlobal("fetch", fetchSpy);
    const xhr = vi.spyOn(XMLHttpRequest.prototype, "open");
    const w = mount(MessageBody, { props: { json: envelope } });
    const r = sealed.recipients[1];
    await pick(w, { ...r.private_jwk, kid: r.kid });
    const plain = w.find("[data-plain]");
    expect(plain.exists()).toBe(true);
    expect(JSON.parse(plain.text())).toEqual(sealed.body);
    expect(w.find('.badge[data-k="plain"]').text()).toBe("Decrypted in this tab");
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(xhr).not.toHaveBeenCalled();
    // the picker is gone with the ciphertext view; nothing holds on to the key file
    expect(w.find('input[type="file"]').exists()).toBe(false);
    vi.unstubAllGlobals();
  });

  it("finds the right recipient for a key file without a kid", async () => {
    const w = mount(MessageBody, { props: { json: envelope } });
    await pick(w, sealed.recipients[0].private_jwk);
    expect(JSON.parse(w.find("[data-plain]").text())).toEqual(sealed.body);
  });

  it("says so when the key is not a recipient's", async () => {
    const w = mount(MessageBody, { props: { json: envelope } });
    const outsider = sealed.negative.find((n: { name: string }) => n.name === "non_recipient");
    await pick(w, outsider.private_jwk);
    expect(w.find("[data-plain]").exists()).toBe(false);
    expect(w.find(".err").text()).toMatch(/does not open the message/);
  });
});
