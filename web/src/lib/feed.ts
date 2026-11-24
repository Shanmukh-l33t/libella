import type { Event } from "../types";

export const FEED_CAP = 400;

/** The activity list is capped for rendering; coverage limits are read from the whole log. */
export function feedView(all: Iterable<Event>) {
  const rows = [...all].sort((a, b) => b.seq - a.seq);
  const degradations = rows.filter((e) => e.kind === "degradation" || e.kind === "engagement_failed").reverse();
  return { events: rows.slice(0, FEED_CAP), degradations };
}
