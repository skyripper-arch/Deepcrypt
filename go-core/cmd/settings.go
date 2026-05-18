package cmd

import (
	"fmt"

	"deepcrypt/internal/settings"

	"github.com/charmbracelet/huh"
)

func interactiveSettings() {
	s := settings.Load()

	// ── Step 1: Machine Lock toggle ───────────────────────────────────────────
	lockEnabled := s.MachineLock.Enabled
	err := newForm(
		huh.NewConfirm().
			Title("  Machine Lock").
			Description("Bind encrypted files to this machine.\n  Disabled = shareable key anyone can use.\n  Enabled  = requires matching hardware to decrypt.").
			Affirmative("Enable").
			Negative("Disable").
			Value(&lockEnabled),
	).Run()
	if aborted(err) {
		return
	}
	s.MachineLock.Enabled = lockEnabled

	if lockEnabled {
		// ── Step 2: Factor selection ──────────────────────────────────────────
		var selected []string
		if s.MachineLock.SaveHWID {
			selected = append(selected, "hwid")
		}
		if s.MachineLock.SaveNetwork {
			selected = append(selected, "network")
		}
		if s.MachineLock.SaveMainboard {
			selected = append(selected, "mainboard")
		}
		if s.MachineLock.SaveProcessorID {
			selected = append(selected, "processorid")
		}
		if s.MachineLock.SaveSerial {
			selected = append(selected, "serial")
		}

		err = newForm(
			huh.NewMultiSelect[string]().
				Title("  Hardware binding factors").
				Description("At least 3 selected factors must match on the decrypting machine.\n  Use SPACE to toggle, ENTER to confirm.").
				Options(
					huh.NewOption("HWID           — Motherboard / product UUID", "hwid"),
					huh.NewOption("Network        — Active local IP addresses", "network"),
					huh.NewOption("Mainboard      — Board serial / model string", "mainboard"),
					huh.NewOption("Processor ID   — CPU unique identifier", "processorid"),
					huh.NewOption("Serial Number  — BIOS system serial number", "serial"),
				).
				Value(&selected),
		).Run()
		if aborted(err) {
			return
		}

		has := func(k string) bool {
			for _, v := range selected {
				if v == k {
					return true
				}
			}
			return false
		}
		s.MachineLock.SaveHWID = has("hwid")
		s.MachineLock.SaveNetwork = has("network")
		s.MachineLock.SaveMainboard = has("mainboard")
		s.MachineLock.SaveProcessorID = has("processorid")
		s.MachineLock.SaveSerial = has("serial")

		// Inline warning about factor count.
		n := s.MachineLock.ActiveCount()
		fmt.Println()
		switch {
		case n == 0:
			fmt.Println("  " + styleErr.Render("⚠  Warning:") + "  No factors selected — machine lock will have no effect on key security.")
		case n == 5:
			fmt.Println("  " + styleYellow.Render("⚠  Warning:") + "  All 5 factors selected — any hardware change may permanently lock you out.")
		case n < 3:
			fmt.Println("  " + styleYellow.Render("⚠  Warning:") +
				fmt.Sprintf("  Only %d factor(s) selected. Decryption requires at least 3 matching — you may be locked out on minor hardware changes.", n))
		default:
			fmt.Println("  " + styleOK.Render("✓") + fmt.Sprintf("  %d factors selected — decryption requires ≥3 to match.", n))
		}
		fmt.Println()
	} else {
		// Clear factors when disabling machine lock.
		s.MachineLock.SaveHWID = false
		s.MachineLock.SaveNetwork = false
		s.MachineLock.SaveMainboard = false
		s.MachineLock.SaveProcessorID = false
		s.MachineLock.SaveSerial = false
	}

	// ── Step 3: Password protection ───────────────────────────────────────────
	pwEnabled := s.UsePassword
	err = newForm(
		huh.NewConfirm().
			Title("  Decryption Password").
			Description("You will be asked to set a password each time you encrypt.\n  Anyone trying to decrypt will need to provide it.").
			Affirmative("Enable").
			Negative("Disable").
			Value(&pwEnabled),
	).Run()
	if aborted(err) {
		return
	}
	s.UsePassword = pwEnabled

	// ── Save ──────────────────────────────────────────────────────────────────
	if err := s.Save(); err != nil {
		printFail("Failed to save settings: " + err.Error())
		return
	}

	fmt.Println()
	printOK("Settings saved.")
	printSettingsSummary(s)
	fmt.Println()
}

// printSettingsSummary shows a one-line status for each setting.
func printSettingsSummary(s *settings.Settings) {
	if s.MachineLock.Enabled {
		n := s.MachineLock.ActiveCount()
		printInfo(fmt.Sprintf("Machine lock  "+styleOK.Render("ON")+"  — %d factor(s) active", n))
	} else {
		printInfo("Machine lock  " + styleDim.Render("OFF") + "  — keys are shareable")
	}
	if s.UsePassword {
		printInfo("Password      " + styleOK.Render("ON") + "  — asked at encrypt time")
	} else {
		printInfo("Password      " + styleDim.Render("OFF"))
	}
}
