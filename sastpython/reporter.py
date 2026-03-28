from collections import Counter, defaultdict
from datetime import datetime
from rich.console import Console
from rich.syntax import Syntax
from rich.align import Align
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table as RLTable, TableStyle, Paragraph, Preformatted, Spacer
import platform

SEVERITY_COLOR = {
    "CRITICAL": "red",
    "HIGH": "orange1",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFO": "cyan"
}

class ConsoleReporter:
    def __init__(self, source_code, issues):
        self.source_code = source_code
        self.issues = issues or []
        self.console = Console()

    def _severity_style(self, sev: str) -> str:
        if not sev:
            return SEVERITY_COLOR["INFO"]
        return SEVERITY_COLOR.get(sev.upper(), SEVERITY_COLOR["INFO"])
    
    def _compute_risk_score(self, sev_counts):
        # Compute a normalized 0–100 risk score based on severity weights.
        weights = {
            "CRITICAL": 10,
            "HIGH": 5,
            "MEDIUM": 2,
            "LOW": 1,
            "INFO": 0
        }

        raw = sum(weights.get(sev, 0) * count for sev, count in sev_counts.items())

        total = sum(sev_counts.values())
        max_raw = total * weights["CRITICAL"]

        if max_raw == 0:
            return 0

        score = int((raw / max_raw) * 100)
        return score

    def print_summary(self, top_n: int = 6, show_chart: bool = True):
        # Print a compact summary of the scan
        if not self.issues:
            self.console.print("[green]✅ No vulnerabilities found.[/green]")
            return

        total = len(self.issues)

        sev_counts = Counter()
        cat_counts = Counter()
        func_counts = Counter()
        by_sev = defaultdict(list)

        for issue in self.issues:
            sev = (issue.get("severity") or "INFO").upper()
            sev_counts[sev] += 1
            by_sev[sev].append(issue)

            cat = issue.get("category") or "Unknown"
            cat_counts[cat] += 1

            func = issue.get("function") or issue.get("code_snippet") or "<unknown>"
            func_counts[func] += 1

        # Order severities by priority for display
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        # Ensure we include any unexpected severities too
        for extra in sorted(set(sev_counts.keys()) - set(severity_order)):
            severity_order.append(extra)

        # --- Top header panel with summary numbers ---
        header_tbl = Table.grid(expand=True)
        header_tbl.add_column("left", ratio=50)
        header_tbl.add_column("right", ratio=50)

        left = Text()
        left.append("Scan summary\n", style="bold")
        left.append(f"Total issues: {total}\n", style="bold yellow")
        left.append(f"Unique categories: {len(cat_counts)}\n")
        left.append(f"Affected functions: {len(func_counts)}")

        sev_table = Table.grid(padding=(0,1))
        sev_table.add_column("sev", no_wrap=True)
        sev_table.add_column("count", no_wrap=True)
        sev_table.add_column("pct", no_wrap=True)
        sev_table.add_column("bar")

        def make_bar(count, max_count, width=20):
            if max_count == 0:
                return ""
            filled = int((count / max_count) * width)
            bar = "█" * filled + "░" * (width - filled)
            return bar

        max_count = max(sev_counts.values()) if sev_counts else 0

        for sev in severity_order:
            cnt = sev_counts.get(sev, 0)
            if cnt == 0:
                continue
            pct = (cnt / total) * 100
            color = self._severity_style(sev)
            bar = make_bar(cnt, max_count)
            sev_table.add_row(
                f"[{color}]{sev}[/]",
                str(cnt),
                f"{pct:.0f}%",
                Text(bar, style=color)
            )

        header_tbl.add_row(left, sev_table)
        self.console.print(Panel(header_tbl, box=box.ROUNDED, title="Summary", border_style="bright_blue"))

        # --- Top categories table ---
        top_cats = cat_counts.most_common(top_n)
        cat_table = Table(title=f"Top {len(top_cats)} Categories", box=box.DOUBLE_EDGE, show_header=True)
        cat_table.add_column("Owasp Category", no_wrap=False)
        cat_table.add_column("Count", justify="right")
        cat_table.add_column("Percent", justify="right")
        for cat, cnt in top_cats:
            pct = cnt / total * 100
            cat_table.add_row(cat, str(cnt), f"{pct:.0f}%")
        self.console.print(cat_table)

        # --- Quick actionable guidance ---
        guidance = Table.grid(expand=True)
        guidance.add_column("left", ratio=50)
        guidance.add_column("right", ratio=50)

        bullets = []
        if sev_counts.get("CRITICAL", 0):
            bullets.append("[bold red]• Fix CRITICAL issues first (high risk of RCE/data loss).[/bold red]")
        if sev_counts.get("HIGH", 0):
            bullets.append("[bold orange1]• Address HIGH severity issues next (privilege escalation, data leaks).[/bold orange1]")
        if sev_counts.get("MEDIUM", 0):
            bullets.append("[yellow]• Triage MEDIUM issues (validate input, add checks, sanitize outputs).[/yellow]")
        if sev_counts.get("LOW", 0):
            bullets.append("[green]• Review LOW issues for hardening and best practices.[/green]")
        if not bullets:
            bullets.append("[green]No actionable issues detected.[/green]")

        left_text = Text.from_markup("\n".join(bullets))

        right_text = Text()
        right_text.append("Suggested workflow:\n", style="bold")
        right_text.append("1. Reproduce & write tests for the vulnerability.\n")
        right_text.append("2. Prioritize fixes by severity & exploitability.\n")
        right_text.append("3. Apply fix + add automated checks (CI tests/security lint).\n")
        right_text.append("4. Run full scan again to confirm remediation.")

        guidance.add_row(left_text, right_text)
        self.console.print(Panel(guidance, box=box.ROUNDED, title="Actionable guidance", border_style="magenta"))

        # --- Short details: show issues for quick peek ---
        quick_peek = Table(box=box.MINIMAL_HEAVY_HEAD, show_header=True)
        quick_peek.add_column("Line", no_wrap=True)
        quick_peek.add_column("Category", no_wrap=False)
        quick_peek.add_column("Severity", no_wrap=True)
        quick_peek.add_column("Vulnerability", no_wrap=False)
        
        for issue in self.issues:
            line = str(issue.get("line", "?"))
            category = issue.get("category", "")
            severity = issue.get("severity", "INFO")
            vuln = issue.get("vulnerability", "")
            
            sev_style = self._severity_style(severity)
            sev_cell = f"[{sev_style}]{severity}[/]"

            quick_peek.add_row(
                line,
                category,
                sev_cell,
                vuln,
            )

        self.console.print(Panel(quick_peek, box=box.ROUNDED, title="Quick peek (examples)", border_style="cyan"))

        # --- Footer panel: risk score + metadata ---
        footer = Table.grid(expand=True)
        footer.add_column(justify="center")

        risk_score = self._compute_risk_score(sev_counts)

        risk_text = Text()
        risk_text.append("Overall Risk Score\n", style="bold underline")
        risk_text.append(f"{risk_score}/100\n", style="bold yellow")

        if risk_score >= 70:
            risk_label = Text.from_markup("[bold red]High Risk[/bold red]")
        elif risk_score >= 40:
            risk_label = Text.from_markup("[bold orange1]Moderate Risk[/bold orange1]")
        else:
            risk_label = Text.from_markup("[bold green]Low Risk[/bold green]")

        risk_text.append(risk_label)
        risk_text.append("\n")

        metadata = Text()
        metadata.append("Scan Metadata\n", style="bold underline")

        metadata.append(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        metadata.append(f"Scanner Version: 1.0.0\n")
        metadata.append(f"Total Issues: {total}\n")
        metadata.append(f"Categories Detected: {len(cat_counts)}\n")
        metadata.append(f"Host Machine: {platform.system()} {platform.release()}")

        footer.add_row(risk_text)
        footer.add_row(metadata)

        self.console.print(
            Panel(
                footer,
                box=box.ROUNDED,
                border_style="bright_green",
                title="Footnote",
                title_align="center",
            )
        )

        # End of summary
        self.console.print()  # small trailing space

    def print_detail(self, use_borders: bool = True, box_style: str = "ROUNDED", show_issue_header: bool = True):
        # Pretty 2-column stacked tables
        if not self.issues:
            self.console.print("[green]✅ No vulnerabilities found.[/green]")
            return

        box_map = {
            "ROUNDED": box.ROUNDED,
            "SIMPLE": box.SIMPLE,
            "SIMPLE_HEAVY": box.SIMPLE_HEAVY,
            "MINIMAL": box.MINIMAL,
            "DOUBLE": box.DOUBLE,
            "SQUARE": box.SQUARE,
            "ASCII": box.ASCII,
        }
        chosen_box = box_map.get(box_style.upper(), box.ROUNDED)

        self.console.print("\n[bold underline]Detailed report:[/bold underline]\n")

        for idx, issue in enumerate(self.issues, start=1):
            tbl = Table.grid(expand=True)
            tbl.add_column("label", ratio=15, no_wrap=True, style="bold")
            tbl.add_column("value", ratio=85, overflow="fold")

            line = str(issue.get("line", "?"))
            snippet = issue.get("code_snippet", issue.get("function", "")) or ""
            category = issue.get("category", "-")
            ruleid = str(issue.get("rule", "-"))
            vuln = issue.get("vulnerability", "-")
            severity = (issue.get("severity") or "INFO").upper()
            desc = issue.get("description", "-")
            recomm = issue.get("recommendation", "-")

            sev_color = self._severity_style(severity) or "white"
            sev_icon = {
                "CRITICAL": "🔥",
                "HIGH": "🔴",
                "MEDIUM": "🟠",
                "LOW": "🔵",
                "INFO": "ℹ️"
            }.get(severity, "ℹ️")
            sev_badge = Text.assemble((f"{sev_icon} ", ""), (f"{severity}", f"bold {sev_color}"))

            # Code snippet: Syntax if present, otherwise plain
            if snippet:
                try:
                    code_render = Syntax(snippet, "python", line_numbers=False, word_wrap=True)
                except Exception:
                    code_render = Text(snippet, overflow="fold")
            else:
                code_render = Text("-", style="dim")

            tbl.add_row("Line number", line)
            tbl.add_row("Code Snippet", code_render)
            tbl.add_row("Category", category)
            tbl.add_row("Rule ID", ruleid)
            tbl.add_row("Vulnerability", vuln)
            tbl.add_row("Severity", sev_badge)
            tbl.add_row("Description", Text(desc, overflow="fold"))
            tbl.add_row("Recommendation", Text(recomm, overflow="fold"))

            if use_borders:
                header = None
                if show_issue_header:
                    header_text = Text.assemble(
                        ("Issue ", "bold"),
                        (f"#{idx}", "bold yellow"),
                    )
                    header = header_text

                panel = Panel(
                    Align.left(tbl),
                    box=chosen_box,
                    title=header,
                    title_align="left",
                    padding=(0, 1),
                    expand=True,
                    border_style="dim"
                )
                self.console.print(panel)
            else:
                self.console.print(tbl)

            if idx != len(self.issues):
                self.console.print()

    def export_pdf(self, output_path: str, page_size="A4"):
        #Export the same report to a PDF file using ReportLab.
        pagesize = A4 if page_size == "A4" else letter
        doc = SimpleDocTemplate(output_path,
                                pagesize=pagesize,
                                rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=18)

        styles = getSampleStyleSheet()
        title_style = styles["Title"]
        subtitle_style = styles["Heading2"]
        body_style = styles["BodyText"]
        body_style.fontSize = 9
        body_style.leading = 11

        elems = [Paragraph("Static Code Analysis Report", title_style), Spacer(1, 12)]

        if not self.issues:
            elems.append(Paragraph("✅ No vulnerabilities found.", body_style))
            try:
                doc.build(elems)
            except Exception as e:
                raise RuntimeError(f"Failed to build PDF: {e}")
            return

        # --- Compute summary data ---
        from collections import Counter
        import platform
        from datetime import datetime

        sev_counts = Counter()
        cat_counts = Counter()
        func_counts = Counter()
        for issue in self.issues:
            sev = (issue.get("severity") or "INFO").upper()
            sev_counts[sev] += 1
            cat = issue.get("category") or "Unknown"
            cat_counts[cat] += 1
            func = issue.get("function") or issue.get("code_snippet") or "<unknown>"
            func_counts[func] += 1

        total = len(self.issues)
        try:
            risk_score = self._compute_risk_score(sev_counts)
        except Exception:
            risk_score = 0

        summary_lines = [
            f"Total issues: {total}",
            f"Unique categories: {len(cat_counts)}",
            f"Affected functions: {len(func_counts)}",
            f"Overall risk score: {risk_score}/100"
        ]
        elems.append(Paragraph("Summary", subtitle_style))
        for ln in summary_lines:
            elems.append(Paragraph(ln, body_style))
        elems.append(Spacer(1, 8))

        elems.append(Paragraph("Top categories", subtitle_style))
        top_cats = cat_counts.most_common(10)
        if top_cats:
            cat_data = [["Category", "Count", "Percent"]]
            for cat, cnt in top_cats:
                pct = (cnt / total) * 100
                cat_data.append([cat, str(cnt), f"{pct:.0f}%"])

            avail_width = doc.width
            colw = [avail_width * 0.6, avail_width * 0.2, avail_width * 0.2]
            cat_table = RLTable(cat_data, colWidths=colw, hAlign="LEFT", repeatRows=1)
            cat_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2b303b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ]))
            elems.append(cat_table)
            elems.append(Spacer(1, 8))

        # --- Full issues table ---
        elems.append(Paragraph("Full findings", subtitle_style))
        elems.append(Spacer(1, 6))

        code_style = ParagraphStyle(
            name="Code",
            parent=body_style,
            fontName="Courier",
            fontSize=8,
            leading=10,
        )

        left_w = doc.width * 0.18
        right_w = doc.width - left_w

        for issue in self.issues:
            line = str(issue.get("line", "?"))
            snippet = issue.get("function") or "-"
            category = issue.get("category", "-")
            rule = str(issue.get("rule", "-"))
            vuln = issue.get("vulnerability", "-")
            severity = issue.get("severity", "-")
            desc = issue.get("description") or "-"
            recomm = issue.get("recommendation") or "-"

            snippet_para = Preformatted(snippet.replace("\t", "    "), code_style)
            vuln_para = Paragraph(vuln, body_style)
            desc_para = Paragraph(desc, body_style)
            recomm_para = Paragraph(recomm, body_style)
            severity_para = Paragraph(severity, body_style)
            category_para = Paragraph(category, body_style)
            rule_para = Paragraph(rule, body_style)
            line_para = Paragraph(line, body_style)

            issue_data = [
                ["Line number", line_para],
                ["Code Snippet", snippet_para],
                ["Category", category_para],
                ["Rule ID", rule_para],
                ["Vulnerability Name", vuln_para],
                ["Severity Level", severity_para],
                ["Issue Description", desc_para],
                ["Recommendation", recomm_para],
            ]

            issue_table = RLTable(issue_data, colWidths=[left_w, right_w], hAlign="LEFT")
            issue_table.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("LEFTPADDING", (0,0), (-1,-1), 6),
                ("RIGHTPADDING", (0,0), (-1,-1), 6),
                ("TOPPADDING", (0,0), (-1,-1), 4),
                ("BOTTOMPADDING", (0,0), (-1,-1), 4),
                ("BOX", (0,0), (-1,-1), 0.25, colors.grey),
                ("INNERGRID", (0,0), (-1,-1), 0.25, colors.grey),
            ]))

            elems.append(issue_table)
            elems.append(Spacer(1, 6))

        sep = RLTable([[""]], colWidths=[doc.width])
        sep.setStyle(TableStyle([("LINEBELOW", (0,0), (-1,0), 0.5, colors.lightgrey)]))
        elems.append(sep)
        elems.append(Spacer(1, 6))

        # --- Footer metadata on last page ---
        elems.append(Spacer(1, 12))
        meta_lines = [
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Scanner Version: 1.0.0",
            f"Host: {platform.system()} {platform.release()}",
            f"Issues: {total}"
        ]
        for ml in meta_lines:
            elems.append(Paragraph(ml, body_style))

        try:
            doc.build(elems)
        except Exception as e:
            raise RuntimeError(f"Failed to build PDF: {e}")