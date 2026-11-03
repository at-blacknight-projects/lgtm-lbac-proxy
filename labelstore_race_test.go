package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// storeEntries returns the parsed entries of the store's published snapshot.
func storeEntries(s *FileLabelStore) map[string]*LabelPolicy {
	return s.snapshot.Load().entries
}

// newTestLabelStore returns a store serving the given pre-parsed entries.
func newTestLabelStore(parser *PolicyParser, entries map[string]*LabelPolicy) *FileLabelStore {
	s := &FileLabelStore{parser: parser}
	s.snapshot.Store(&policySnapshot{entries: entries})
	return s
}

const raceLabels = `
user:
  _rules:
    - name: namespace
      operator: "="
      values: ["user-ns"]
group1:
  _rules:
    - name: namespace
      operator: "="
      values: ["g1"]
group2:
  _rules:
    - name: namespace
      operator: "="
      values: ["g2"]
`

// labelsDir writes labels.yaml into a temp dir and returns the dir and a rewriter.
func labelsDir(t *testing.T, body string) (string, func(string)) {
	t.Helper()
	dir := t.TempDir()
	write := func(b string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "labels.yaml"), []byte(b), 0o600))
	}
	write(body)
	return dir, write
}

func loadedStore(t *testing.T, dir string) *FileLabelStore {
	t.Helper()
	s := &FileLabelStore{parser: NewPolicyParser()}
	require.NoError(t, s.loadLabels(viper.New(), []string{dir}))
	return s
}

// #7 / #12: concurrent cache misses for new user+groups combinations, while labels.yaml
// reloads. On the old plain map this aborts the process with "concurrent map read and
// map write" (and -race flags it at once); with per-snapshot sync.Map it is clean.
func TestGetLabelPolicyConcurrentWithReload(t *testing.T) {
	dir, write := labelsDir(t, raceLabels)
	store := loadedStore(t, dir)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			write(raceLabels + fmt.Sprintf("\ngroup-%d:\n  _rules:\n    - name: namespace\n      operator: \"=\"\n      values: [\"x\"]\n", i))
			_ = store.loadLabels(viper.New(), []string{dir})
		}
	}()
	var readers sync.WaitGroup
	for i := 0; i < 32; i++ {
		readers.Add(1)
		go func(i int) {
			defer readers.Done()
			for j := 0; j < 200; j++ {
				groups := []string{"group1", fmt.Sprintf("extra-%d", (i+j)%26)}
				if j%2 == 0 {
					groups = append(groups, "group2")
				}
				p, err := store.GetLabelPolicy(UserIdentity{Username: "user", Groups: groups}, "")
				if assert.NoError(t, err) {
					assert.NotEmpty(t, p.Rules)
				}
			}
		}(i)
	}
	readers.Wait()
	close(stop)
	wg.Wait()
}

// A labels.yaml that fails to load is never published: the previous snapshot, and
// every policy merged from it, keep serving.
func TestLabelsReloadFailureKeepsPreviousPolicies(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"unparseable yaml", "user: [unclosed\n"},
		{"simple (deprecated) format", "user:\n  namespace: true\n"},
		{"invalid rule", "user:\n  _rules:\n    - name: namespace\n      operator: \"<>\"\n      values: [\"a\"]\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, write := labelsDir(t, raceLabels)
			store := loadedStore(t, dir)
			before := store.snapshot.Load()
			merged, err := store.GetLabelPolicy(UserIdentity{Username: "user", Groups: []string{"group1"}}, "")
			require.NoError(t, err)

			write(tt.body)
			assert.Error(t, store.loadLabels(viper.New(), []string{dir}))

			assert.Same(t, before, store.snapshot.Load(), "the previous snapshot keeps serving")
			again, err := store.GetLabelPolicy(UserIdentity{Username: "user", Groups: []string{"group1"}}, "")
			require.NoError(t, err)
			assert.Same(t, merged, again, "including its cached merged policies")
		})
	}
}

// Merged policies belong to the snapshot they were built from: after a reload a user
// gets a policy merged from the new entries, never a stale one.
func TestLabelsReloadDropsMergedPolicies(t *testing.T) {
	dir, write := labelsDir(t, raceLabels)
	store := loadedStore(t, dir)
	id := UserIdentity{Username: "user", Groups: []string{"group1"}}

	p, err := store.GetLabelPolicy(id, "")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"user-ns", "g1"}, p.Rules[0].Values)

	write(`
user:
  _rules:
    - name: namespace
      operator: "="
      values: ["user-ns"]
group1:
  _rules:
    - name: namespace
      operator: "="
      values: ["g1-moved"]
`)
	require.NoError(t, store.loadLabels(viper.New(), []string{dir}))

	p, err = store.GetLabelPolicy(id, "")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"user-ns", "g1-moved"}, p.Rules[0].Values)
}

// Past maxMergedPolicies the cache stops growing; merges are still correct, just not
// cached.
func TestMergedPolicyCacheIsBounded(t *testing.T) {
	dir, _ := labelsDir(t, raceLabels)
	store := loadedStore(t, dir)
	store.snapshot.Load().mergedCount.Store(maxMergedPolicies)

	id := UserIdentity{Username: "user", Groups: []string{"group1"}}
	p, err := store.GetLabelPolicy(id, "")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"user-ns", "g1"}, p.Rules[0].Values)

	_, cached := store.snapshot.Load().merged.Load("merged:user:group1")
	assert.False(t, cached, "nothing is cached past the bound")
	assert.Equal(t, int64(maxMergedPolicies), store.snapshot.Load().mergedCount.Load())
}

func TestGetLabelPolicyBeforeLoad(t *testing.T) {
	_, err := (&FileLabelStore{}).GetLabelPolicy(UserIdentity{Username: "user"}, "")
	assert.ErrorContains(t, err, "not loaded")
}
