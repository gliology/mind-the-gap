# A restrained kernel and a machine that only ever powers off: what the retired hardened
# profile used to carry, plus the discipline that keeps RAM holding as little history as
# possible.
{ lib, pkgs, ... }:

{
  # The hardened kernel flavour was removed from nixpkgs 26.05 for lack of maintenance, so
  # this runs the default kernel and keeps its hardening explicit: the locked modules
  # and blacklisted radios of the airgap module, plus a restrained kernel attack surface for anything
  # unprivileged that might run during a session. The lockdown LSM would be the natural
  # next step, but the default kernel compiles it out and turning it on means building a
  # kernel of our own on every CI run; over strict /dev/mem (on by default) and the kexec
  # lock below it adds little under a threat model that already concedes possession.
  boot.kernel.sysctl = {
    "kernel.dmesg_restrict" = 1;
    "kernel.kptr_restrict" = 2;
    "kernel.perf_event_paranoid" = 3;
    "kernel.unprivileged_bpf_disabled" = 1;
    "net.core.bpf_jit_harden" = 2;
    "kernel.sysrq" = 0;
    # Nothing on this image has any business tracing another process, and the one
    # process worth attacking holds a seed phrase in memory
    "kernel.yama.ptrace_scope" = 3;
    # Kernel interfaces nothing here uses: io_uring, user page faults, and tty line
    # disciplines autoloaded from userspace, which is a module loader in disguise that
    # survives the module lock
    "kernel.io_uring_disabled" = 2;
    "vm.unprivileged_userfaultfd" = 0;
    "dev.tty.ldisc_autoload" = 0;
  };

  # The kernel that booted is the kernel that runs: no kexec into another one, which
  # could read this one's memory at leisure, and no hibernation image
  security.protectKernelImage = true;

  # Zero freed pages immediately. Secrets the tools already wipe are covered either way;
  # this extends the same discipline to every allocation the kernel hands back, so RAM
  # holds as little history as possible at any moment. It narrows what a warm reboot or
  # cold boot attack can find, though true immunity is not reachable in software: power
  # the machine off and let it sit before walking away.
  #
  # The rest is what the retired hardened profile used to carry and costs nothing here: a
  # random stack offset per syscall, no slab cache merging (keeps unrelated heap objects
  # apart), no legacy vsyscall page, no debugfs, and an oops panics instead of limping on
  # with a kernel of unknown state. mem_encrypt=on asks AMD machines with SME to encrypt
  # RAM transparently, the one thing that actually blunts a cold boot attack; firmware
  # without it ignores the parameter, and Intel TME has no switch but the firmware's own.
  boot.kernelParams = [
    "init_on_alloc=1"
    "init_on_free=1"
    "efi_pstore.pstore_disable=1"
    "randomize_kstack_offset=on"
    "slab_nomerge"
    "debugfs=off"
    "oops=panic"
  ]
  ++ lib.optionals pkgs.stdenv.hostPlatform.isx86_64 [
    "vsyscall=none"
    "mem_encrypt=on"
  ];

  # Power off is the only way out of a session. Suspend keeps the seed phrase in RAM
  # behind a dark screen, and a closed laptop lid would do exactly that by default while
  # the machine looks off to whoever walks away from it. Hibernation is refused
  # besides.
  systemd.sleep.settings.Sleep = {
    AllowSuspend = "no";
    AllowHibernation = "no";
    AllowHybridSleep = "no";
    AllowSuspendThenHibernate = "no";
  };
  services.logind.settings.Login = {
    HandleLidSwitch = "ignore";
    HandleLidSwitchExternalPower = "ignore";
    HandleLidSwitchDocked = "ignore";
  };

  # pstore is firmware-backed persistence: kernel crash records written to EFI variables
  # survive power-off and carry dmesg, registers and stack contents. The kernel parameter
  # above keeps the EFI backend from registering at all, so nothing can be deposited there
  # in the first place.
}
