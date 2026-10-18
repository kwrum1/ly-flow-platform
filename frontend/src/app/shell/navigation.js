import { productNavigation, canAccessNavigationItem } from '../../shared/navigation'

export function visibleGroups(role) {
  return productNavigation
    .map((group) => ({
      ...group,
      items: group.items.filter((item) => canAccessNavigationItem(item, role)),
    }))
    .filter((group) => group.items.length > 0)
}

export function activeGroupForPath(path, groups = visibleGroups('admin')) {
  return groups.find((group) => group.items.some((item) => path === item.path || path.startsWith(`${item.path}/`))) || groups[0]
}

export function activeItemsForPath(path, role) {
  const groups = visibleGroups(role)
  const group = activeGroupForPath(path, groups)
  return group ? group.items : []
}
