export interface Session {
  id: string;
  name: string;
  operator: string;
  target?: string;
  status: string;
}

export interface Finding {
  id: string;
  title: string;
  severity: string;
  target: string;
  module: string;
}
