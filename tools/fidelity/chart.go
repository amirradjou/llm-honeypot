package main

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"os"
	"strings"
)

// groupScore is one row of the before/after chart.
type groupScore struct {
	name          string
	total         int
	before, after int
}

func loadResults(path string) ([]result, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rs []result
	return rs, json.Unmarshal(b, &rs)
}

// scores pairs the current run with a baseline run of the same corpus,
// group by group, with an "All lines" row first.
func scores(now, before []result) []groupScore {
	prev := map[string]bool{}
	for _, r := range before {
		prev[r.Family+"\x00"+r.Command] = r.Match
	}
	var order []string
	byName := map[string]*groupScore{}
	all := &groupScore{name: "All lines"}
	for _, r := range now {
		g, ok := byName[r.Family]
		if !ok {
			g = &groupScore{name: r.Family}
			byName[r.Family] = g
			order = append(order, r.Family)
		}
		for _, s := range []*groupScore{g, all} {
			s.total++
			if r.Match {
				s.after++
			}
			if prev[r.Family+"\x00"+r.Command] {
				s.before++
			}
		}
	}
	out := []groupScore{*all}
	for _, name := range order {
		out = append(out, *byName[name])
	}
	return out
}

// writeChart draws a dumbbell chart: one row per group, a light dot for
// the baseline share of matching lines and a dark dot for the current one.
// Colours follow the light/dark preference of whoever views it.
func writeChart(w io.Writer, rows []groupScore) {
	const (
		width    = 820
		labelW   = 178
		plotX0   = 196
		plotX1   = 636
		valueX   = 664
		top      = 104
		rowH     = 34
		dotR     = 5.5
		fontFace = `system-ui, -apple-system, "Segoe UI", sans-serif`
	)
	height := top + rowH*len(rows) + 46
	x := func(n, total int) float64 {
		return plotX0 + float64(plotX1-plotX0)*float64(n)/float64(max(total, 1))
	}
	all := rows[0]
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" role="img" aria-labelledby="t d">`+"\n", width, height, width, height)
	fmt.Fprintf(&b, `<title id="t">Bot command lines that behave like a real Ubuntu 22.04 server</title>`+"\n")
	fmt.Fprintf(&b, `<desc id="d">%d of %d lines matched before this work and %d of %d after.</desc>`+"\n", all.before, all.total, all.after, all.total)
	b.WriteString(`<style>
  .s{fill:#fcfcfb}.ink{fill:#0b0b0b}.ink2{fill:#52514e}.mute{fill:#898781}
  .grid{stroke:#e1e0d9;stroke-width:1}.base{stroke:#c3c2b7;stroke-width:1}
  .b{fill:#86b6ef}.a{fill:#2a78d6;stroke:#fcfcfb;stroke-width:2}.link{stroke:#86b6ef;stroke-width:2}
  @media (prefers-color-scheme: dark){
    .s{fill:#1a1a19}.ink{fill:#f0efec}.ink2{fill:#c3c2b7}
    .grid{stroke:#2c2c2a}.base{stroke:#383835}
    .b{fill:#184f95}.a{fill:#3987e5;stroke:#1a1a19}.link{stroke:#184f95}
  }
  text{font-family:` + fontFace + `}
</style>
`)
	fmt.Fprintf(&b, `<rect class="s" x="0" y="0" width="%d" height="%d" rx="12"/>`+"\n", width, height)
	fmt.Fprintf(&b, `<text class="ink" x="24" y="36" font-size="17" font-weight="600">Can a bot tell it is not a real server?</text>`+"\n")
	fmt.Fprintf(&b, `<text class="ink2" x="24" y="58" font-size="13">Share of %d bot-style command lines that get the same answer as on a real Ubuntu 22.04 box.</text>`+"\n", all.total)
	// Legend.
	fmt.Fprintf(&b, `<circle class="b" cx="30" cy="80" r="%.1f"/><text class="ink2" x="42" y="84.5" font-size="13">before</text>`+"\n", dotR)
	fmt.Fprintf(&b, `<circle class="a" cx="102" cy="80" r="%.1f"/><text class="ink2" x="114" y="84.5" font-size="13">now</text>`+"\n", dotR+1)

	plotBottom := top + rowH*len(rows) - 8
	for _, pct := range []int{0, 25, 50, 75, 100} {
		gx := plotX0 + float64(plotX1-plotX0)*float64(pct)/100
		cls := "grid"
		if pct == 0 {
			cls = "base"
		}
		fmt.Fprintf(&b, `<line class="%s" x1="%.1f" y1="%d" x2="%.1f" y2="%d"/>`+"\n", cls, gx, top-14, gx, plotBottom)
		fmt.Fprintf(&b, `<text class="mute" x="%.1f" y="%d" font-size="12" text-anchor="middle">%d%%</text>`+"\n", gx, plotBottom+18, pct)
	}
	for i, r := range rows {
		cy := top + rowH*i + 6
		weight := "400"
		if i == 0 {
			weight = "600"
		}
		fmt.Fprintf(&b, `<text class="ink" x="%d" y="%d" font-size="13.5" font-weight="%s" text-anchor="end">%s</text>`+"\n", labelW, cy+4, weight, html.EscapeString(r.name))
		bx, ax := x(r.before, r.total), x(r.after, r.total)
		if ax-bx > 2*dotR {
			fmt.Fprintf(&b, `<line class="link" x1="%.1f" y1="%d" x2="%.1f" y2="%d"/>`+"\n", bx, cy, ax, cy)
		}
		fmt.Fprintf(&b, `<circle class="b" cx="%.1f" cy="%d" r="%.1f"/>`+"\n", bx, cy, dotR)
		// The surface ring eats into the fill, so the "now" dot is drawn one
		// pixel larger to look the same size as "before".
		fmt.Fprintf(&b, `<circle class="a" cx="%.1f" cy="%d" r="%.1f"/>`+"\n", ax, cy, dotR+1)
		fmt.Fprintf(&b, `<text class="ink2" x="%d" y="%d" font-size="13" font-weight="%s">%d → %d of %d</text>`+"\n", valueX, cy+4, weight, r.before, r.after, r.total)
		if i == 0 {
			fmt.Fprintf(&b, `<line class="grid" x1="24" y1="%d" x2="%d" y2="%d"/>`+"\n", cy+rowH/2+1, width-24, cy+rowH/2+1)
		}
	}
	b.WriteString("</svg>\n")
	_, _ = io.WriteString(w, b.String())
}
