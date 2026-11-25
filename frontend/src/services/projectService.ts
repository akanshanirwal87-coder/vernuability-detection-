import { api } from './api';
import type { Project, ProjectCreateInput, ProjectUpdateInput, PaginatedProjects } from '../types/project';
import type { ApiResponse } from '../types/auth';

export class ProjectService {
  static async listProjects(params?: {
    skip?: number;
    limit?: number;
    search?: string;
    sort_by?: string;
    sort_order?: 'asc' | 'desc';
  }): Promise<PaginatedProjects> {
    const res = await api.get<ApiResponse<PaginatedProjects>>('/api/v1/projects', {
      params: {
        skip: params?.skip ?? 0,
        limit: params?.limit ?? 20,
        search: params?.search,
        sort_by: params?.sort_by ?? 'created_at',
        sort_order: params?.sort_order ?? 'desc',
      },
    });
    return res.data.data;
  }

  static async getProject(projectId: string): Promise<Project> {
    const res = await api.get<ApiResponse<Project>>(`/api/v1/projects/${projectId}`);
    return res.data.data;
  }

  static async createProject(input: ProjectCreateInput): Promise<Project> {
    const res = await api.post<ApiResponse<Project>>('/api/v1/projects', input);
    return res.data.data;
  }

  static async updateProject(projectId: string, input: ProjectUpdateInput): Promise<Project> {
    const res = await api.put<ApiResponse<Project>>(`/api/v1/projects/${projectId}`, input);
    return res.data.data;
  }

  static async deleteProject(projectId: string): Promise<void> {
    await api.delete(`/api/v1/projects/${projectId}`);
  }
}

export default ProjectService;
