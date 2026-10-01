package patterns

import "sort"

type moduleItem struct {
	key           string
	typeName      string
	visibility    itemVisibility
	source        string
	references    []string
	prerequisites []string
	helpers       map[string]bool
}

type itemVisibility int

const (
	private itemVisibility = iota
	exported
)

func inNewspaperOrder(items []*moduleItem) []*moduleItem {
	byKey := map[string]*moduleItem{}
	for _, item := range items {
		byKey[item.key] = item
	}
	items = liveItems(items, byKey)
	starts := traversalStarts(items, byKey)
	levels := abstractionLevels(starts, byKey)
	ranks := firstUseRanks(starts, byKey)

	ordered := append([]*moduleItem(nil), items...)
	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if levels[a] != levels[b] {
			return levels[a] < levels[b]
		}
		return ranks[a] < ranks[b]
	})
	return withPrerequisitesFirst(ordered, byKey)
}

func liveItems(items []*moduleItem, byKey map[string]*moduleItem) []*moduleItem {
	live := map[*moduleItem]bool{}
	var mark func(item *moduleItem)
	mark = func(item *moduleItem) {
		if live[item] {
			return
		}
		live[item] = true
		for _, target := range item.referencedItems(byKey) {
			mark(target)
		}
		for _, prerequisite := range item.prerequisiteItems(byKey) {
			mark(prerequisite)
		}
	}
	for _, item := range items {
		if item.visibility == exported {
			mark(item)
		}
	}
	var result []*moduleItem
	for _, item := range items {
		if live[item] {
			result = append(result, item)
		}
	}
	return result
}

func traversalStarts(items []*moduleItem, byKey map[string]*moduleItem) []*moduleItem {
	referenced := map[*moduleItem]bool{}
	for _, item := range items {
		for _, target := range item.referencedItems(byKey) {
			referenced[target] = true
		}
	}
	var roots, rest []*moduleItem
	for _, item := range items {
		if referenced[item] {
			rest = append(rest, item)
		} else {
			roots = append(roots, item)
		}
	}
	return append(roots, rest...)
}

func abstractionLevels(starts []*moduleItem, byKey map[string]*moduleItem) map[*moduleItem]int {
	callees := map[*moduleItem][]*moduleItem{}
	visited := map[*moduleItem]bool{}
	onStack := map[*moduleItem]bool{}
	var postorder []*moduleItem
	var visit func(item *moduleItem)
	visit = func(item *moduleItem) {
		visited[item] = true
		onStack[item] = true
		for _, target := range item.referencedItems(byKey) {
			if onStack[target] {
				continue
			}
			callees[item] = append(callees[item], target)
			if !visited[target] {
				visit(target)
			}
		}
		onStack[item] = false
		postorder = append(postorder, item)
	}
	for _, item := range starts {
		if !visited[item] {
			visit(item)
		}
	}

	levels := map[*moduleItem]int{}
	for i := len(postorder) - 1; i >= 0; i-- {
		caller := postorder[i]
		for _, callee := range callees[caller] {
			levels[callee] = max(levels[callee], levels[caller]+1)
		}
	}
	return levels
}

func firstUseRanks(starts []*moduleItem, byKey map[string]*moduleItem) map[*moduleItem]int {
	ranks := map[*moduleItem]int{}
	var queue []*moduleItem
	discover := func(item *moduleItem) {
		if _, seen := ranks[item]; !seen {
			ranks[item] = len(ranks)
			queue = append(queue, item)
		}
	}
	for _, start := range starts {
		discover(start)
		for len(queue) > 0 {
			item := queue[0]
			queue = queue[1:]
			for _, target := range item.referencedItems(byKey) {
				discover(target)
			}
		}
	}
	return ranks
}

func withPrerequisitesFirst(items []*moduleItem, byKey map[string]*moduleItem) []*moduleItem {
	placed := map[*moduleItem]bool{}
	var ordered []*moduleItem
	var place func(item *moduleItem)
	place = func(item *moduleItem) {
		if placed[item] {
			return
		}
		placed[item] = true
		for _, prerequisite := range item.prerequisiteItems(byKey) {
			place(prerequisite)
		}
		ordered = append(ordered, item)
	}
	for _, item := range items {
		place(item)
	}
	return ordered
}

func (item *moduleItem) referencedItems(byKey map[string]*moduleItem) []*moduleItem {
	var targets []*moduleItem
	for _, key := range item.references {
		if target, isItem := byKey[key]; isItem && target != item {
			targets = append(targets, target)
		}
	}
	return targets
}

func (item *moduleItem) prerequisiteItems(byKey map[string]*moduleItem) []*moduleItem {
	var prerequisites []*moduleItem
	for _, key := range item.prerequisites {
		if prerequisite, isItem := byKey[key]; isItem {
			prerequisites = append(prerequisites, prerequisite)
		}
	}
	return prerequisites
}
