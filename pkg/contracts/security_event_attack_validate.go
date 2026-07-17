package contracts

import "errors"

func validateAttackTacticID(value string) error {
	if value == "" {
		return nil
	}
	if len(value) != 6 || value[:2] != "TA" || !isAllDigits(value[2:]) {
		return errors.New("security event: ATT&CK tactic invalid")
	}
	return nil
}

func validateAttackTechniqueID(value string) error {
	if value == "" {
		return nil
	}
	if len(value) == 5 && value[0] == 'T' && isAllDigits(value[1:]) {
		return nil
	}
	if len(value) == 9 && value[0] == 'T' && value[5] == '.' && isAllDigits(value[1:5]) && isAllDigits(value[6:]) {
		return nil
	}
	return errors.New("security event: ATT&CK technique invalid")
}

func isAllDigits(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return len(value) > 0
}
