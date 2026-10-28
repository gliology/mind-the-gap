# Pin and touch policies

Every key on a card can ask for the pin, for a touch of the card's button, for both or for
neither, and both applets fix that per key when the key is imported. mind-the-gap takes the
decision as one word, `--policy`, and maps it onto what each applet can express:

```
mtg> init --policy strict
mtg> upload --policy strict
mtg> upload --app pgp --policy never-touch
```

`init` applies the mode to PIV management access, `upload` to the keys (and to management
access again, when `--policy` is given). Without `--policy` both use `relaxed`, and keys already
on a card keep what they have. `set policy=strict` makes a mode the default for a session, a
[config file](configuration.md) for good.

## The modes

The first three follow the pin rules of NIST SP 800-73-4, the PIV standard: the signature
slot 9C asks for the pin before every single signature, the others once per session. They
differ only in touch. The other modes apply one pin and one touch requirement to every key
alike.

| Mode | PIV 9A, 9D and retired slots | PIV 9C | PIV management access | OpenPGP signing pin | OpenPGP touch |
|---|---|---|---|---|---|
| `strict` | pin once, touch always | pin always, touch always | touch | before every signature | always |
| `relaxed` (default) | pin once, touch cached | pin always, touch always | touch | once per session | cached |
| `never-touch` | pin once, no touch | pin always, no touch | no touch | once per session | off |
| `always` | pin always, touch always | pin always, touch always | touch | before every signature | always |
| `once-always` | pin once, touch always | pin once, touch always | touch | once per session | always |
| `once-cached` | pin once, touch cached | pin once, touch cached | touch | once per session | cached |
| `always-touch` | no pin, touch always | no pin, touch always | touch | once per session | always |
| `cached-touch` | no pin, touch cached | no pin, touch cached | touch | once per session | cached |
| `always-pin` | pin always, no touch | pin always, no touch | no touch | before every signature | off |
| `once-pin` | pin once, no touch | pin once, no touch | no touch | once per session | off |
| `never` | no pin, no touch | no pin, no touch | no touch | once per session | off |

A cached touch is valid for about fifteen seconds, so a burst of operations takes one press.
Management access is what `check` and `upload` authenticate with on PIV; it asks for a touch
whenever the mode asks for touch at all, since administering the card weighs at least as
much as using one of its keys.

Two things hold in every mode:

- **Slot 9E** stays without pin and touch. The standard requires the card authentication key
  to work without the cardholder, for door readers and the like.
- **An OpenPGP card cannot drop the pin.** Every key wants it at least once per session, so
  the modes without a pin mean once per session there, and `upload` says so.

`upload` warns about what a mode gives up before it touches the card: `never` loudly, since
whoever holds the card can then use every key on it, and every mode that lets 9C sign
without a fresh pin, since the standard asks for that pin so that a signature stays
non-repudiable. A host's card is the usual reason to accept that (see [unattended
hosts](unattended-host.md), which use `once-pin`).

PIV on YubiKey firmware before 4.3 has no cached touch, and `upload` refuses a cached mode
there before it writes anything. Several OpenPGP applets lack it as well (a YubiKey 4's,
the Nitrokey 3's opcard, Gnuk); there `upload` falls back to touch always on OpenPGP and says
so.

### Fixed touch

`upload --fixed-touch` makes the OpenPGP touch setting unchangeable but by replacing the
key, where the card offers that (YubiKeys); elsewhere the plain setting is used and
`upload` says so. A PIV touch policy is fixed by nature: it can only change with the key.

## What other tools do

Every other tool leaves the policies to the card, and the cards default to the standard's
pins without any touch, which is the `never-touch` mode. mind-the-gap alone adds touch by
default.

| | 9A | 9C | 9D, retired | 9E | management access | OpenPGP touch | OpenPGP signing pin |
|---|---|---|---|---|---|---|---|
| YubiKey 5.7.4, measured | once, no touch | always, no touch | once, no touch | never, no touch | no touch | off | once per session |
| piv-authenticator (Nitrokey 3, Solo 2) | once, no touch | always, no touch | once, no touch | never, no touch | no touch | | |
| opcard (Nitrokey 3, Solo 2) | | | | | | off | before every signature |
| ykman, yubico-piv-tool | the card decides | | | | | | |

The YubiKey row was read back from a freshly reset key with keys generated under the default
policy; the others come from the applets' sources.
