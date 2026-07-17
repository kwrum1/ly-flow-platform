package features

import (
	"sort"
	"strings"

	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

type entityGroup struct {
	aliases map[string]struct{}
	events  map[string]struct{}
}

func normalizedEntities(events []*models.CanonicalEventV2) models.EntityFeatureSet {
	groups := make([]entityGroup, 0)
	for _, event := range events {
		aliases := eventAliases(event)
		matching := make([]int, 0)
		for index := range groups {
			if intersects(groups[index].aliases, aliases) {
				matching = append(matching, index)
			}
		}
		merged := entityGroup{aliases: toSet(aliases), events: map[string]struct{}{event.EventUID: {}}}
		for index := len(matching) - 1; index >= 0; index-- {
			groupIndex := matching[index]
			mergeSet(merged.aliases, groups[groupIndex].aliases)
			mergeSet(merged.events, groups[groupIndex].events)
			groups = append(groups[:groupIndex], groups[groupIndex+1:]...)
		}
		groups = append(groups, merged)
	}
	normalized := make([]models.NormalizedEntity, 0, len(groups))
	aliasCount := 0
	for _, group := range groups {
		aliases := sortedSet(group.aliases)
		eventUIDs := sortedSet(group.events)
		aliasCount += len(aliases)
		normalized = append(normalized, models.NormalizedEntity{ID: canonicalEntityID(aliases), Aliases: aliases, EventUIDs: eventUIDs})
	}
	sort.Slice(normalized, func(left, right int) bool { return normalized[left].ID < normalized[right].ID })
	return models.EntityFeatureSet{EntityCount: len(normalized), AliasCount: aliasCount, Entities: normalized}
}

func eventAliases(event *models.CanonicalEventV2) []string {
	values := []struct{ prefix, value string }{
		{"host:", event.HostID}, {"agent:", event.AgentID}, {"asset:", event.VictimAsset},
	}
	ip := event.NormalizedDstIP
	if ip == "" {
		ip = event.NormalizedSrcIP
	}
	values = append(values, struct{ prefix, value string }{"ip:", ip})
	aliases := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value.value))
		if normalized != "" {
			aliases = append(aliases, value.prefix+normalized)
		}
	}
	if len(aliases) == 0 {
		aliases = append(aliases, "event:"+strings.ToLower(strings.TrimSpace(event.EventUID)))
	}
	sort.Strings(aliases)
	return aliases
}

func canonicalEntityID(aliases []string) string {
	for _, prefix := range []string{"host:", "agent:", "asset:", "ip:", "event:"} {
		for _, alias := range aliases {
			if strings.HasPrefix(alias, prefix) {
				return alias
			}
		}
	}
	return ""
}

func toSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}

func intersects(left map[string]struct{}, right []string) bool {
	for _, value := range right {
		if _, exists := left[value]; exists {
			return true
		}
	}
	return false
}

func mergeSet(destination, source map[string]struct{}) {
	for value := range source {
		destination[value] = struct{}{}
	}
}

func sortedSet(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
