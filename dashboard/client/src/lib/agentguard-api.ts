export type SourceType = "email" | "file" | "web";
export type ApprovalStatus = "pending" | "approved" | "rejected" | "not_required";

export type SecurityEvent = {
  id: string;
  timestamp: string;
  source_type: SourceType;
  untrusted_content: string;
  sanitized_content?: string | null;
  threat_category?: string | null;
  risk_score: number;
  policy_action: string;
  approval_status: ApprovalStatus;
};

export type QuarantineItem = {
  queue_id: number;
  event_id: string;
  content: string;
  status: ApprovalStatus;
  created_at: string;
  reviewed_at?: string | null;
  reviewer?: string | null;
  risk_score: number;
  threat_category?: string | null;
  source_type: SourceType;
};

export type ConnectionState = "live" | "demo" | "loading";

const API_BASE = (import.meta.env.VITE_AGENTGUARD_API_URL || "http://localhost:8000").replace(/\/$/, "");

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
  });
  if (!response.ok) throw new Error(`AgentGuard API returned ${response.status}`);
  return response.json() as Promise<T>;
}

export async function fetchQueue(): Promise<QuarantineItem[]> {
  return request<QuarantineItem[]>("/quarantine?status=pending&limit=100");
}

export async function fetchEvents(): Promise<SecurityEvent[]> {
  try {
    return await request<SecurityEvent[]>("/logs?limit=100");
  } catch {
    const queue = await fetchQueue();
    return queue.map((item) => ({
      id: item.event_id,
      timestamp: item.created_at,
      source_type: item.source_type,
      untrusted_content: item.content,
      threat_category: item.threat_category,
      risk_score: item.risk_score,
      policy_action: "quarantine",
      approval_status: item.status,
    }));
  }
}

export async function reviewQueueItem(eventId: string, action: "approve" | "reject", reviewer: string): Promise<void> {
  await request(`/quarantine/${eventId}/${action}`, {
    method: "POST",
    body: JSON.stringify({ reviewer }),
  });
}

export { API_BASE };
