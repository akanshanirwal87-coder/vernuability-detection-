export interface Project {
  id: string;
  user_id?: string;
  name: string;
  description?: string | null;
  repository_url?: string | null;
  created_at: string;
  updated_at?: string;
  total_scans?: number;
  latest_risk_score?: number;
  language?: string;
  default_branch?: string;
}

export interface ProjectCreateInput {
  name: string;
  description?: string;
  repository_url?: string;
  language?: string;
  default_branch?: string;
}

export interface ProjectUpdateInput {
  name?: string;
  description?: string;
  repository_url?: string;
}

export interface PaginationMeta {
  total: number;
  skip: number;
  limit: number;
  has_more: boolean;
}

export interface PaginatedProjects {
  items: Project[];
  pagination: PaginationMeta;
}
