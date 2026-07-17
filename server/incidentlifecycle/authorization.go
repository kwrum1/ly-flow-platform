package incidentlifecycle

func authorize(actor Actor, action Action) error {
	if actor.ID == "" {
		return ErrForbidden
	}
	switch actor.Role {
	case RoleAdmin, RoleAnalyst:
		switch action {
		case ActionTransition, ActionAssign, ActionSuppress:
			return nil
		case ActionCreate, ActionSnapshot:
			return ErrForbidden
		default:
			return ErrForbidden
		}
	case RoleSystem:
		if action == ActionSnapshot {
			return nil
		}
		return ErrForbidden
	case RoleViewer:
		return ErrForbidden
	default:
		return ErrForbidden
	}
}
