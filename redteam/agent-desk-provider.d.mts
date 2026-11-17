export default class AgentDeskExtract {
  id(): string;
  callApi(prompt: string): Promise<{ output?: string; error?: string; tokenUsage?: { prompt?: number; completion?: number } }>;
}
