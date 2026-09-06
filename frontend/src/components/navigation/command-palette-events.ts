/** Split from CommandPalette.tsx so that file exports only the component
 * (keeps React Fast Refresh happy — see oxlint's react(only-export-
 * components) rule). */
export const COMMAND_PALETTE_EVENT = "open-command-palette";

export function openCommandPalette() {
  window.dispatchEvent(new Event(COMMAND_PALETTE_EVENT));
}
