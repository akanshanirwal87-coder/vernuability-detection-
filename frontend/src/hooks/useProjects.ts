import { useState, useEffect, useCallback } from 'react';
import { ProjectService } from '../services/projectService';
import type { Project, ProjectCreateInput, ProjectUpdateInput } from '../types/project';

export function useProjects() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchProjects = useCallback(async (params?: { search?: string; skip?: number; limit?: number }) => {
    setLoading(true);
    setError(null);
    try {
      const data = await ProjectService.listProjects(params);
      setProjects(data.items);
      setTotal(data.pagination.total);
    } catch (err: any) {
      setError(err.response?.data?.message || err.message || 'Failed to load projects');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchProjects();
  }, [fetchProjects]);

  const createProject = async (input: ProjectCreateInput): Promise<Project> => {
    setLoading(true);
    try {
      const created = await ProjectService.createProject(input);
      setProjects((prev) => [created, ...prev]);
      setTotal((t) => t + 1);
      return created;
    } finally {
      setLoading(false);
    }
  };

  const updateProject = async (id: string, input: ProjectUpdateInput): Promise<Project> => {
    const updated = await ProjectService.updateProject(id, input);
    setProjects((prev) => prev.map((p) => (p.id === id ? updated : p)));
    return updated;
  };

  const deleteProject = async (id: string): Promise<void> => {
    await ProjectService.deleteProject(id);
    setProjects((prev) => prev.filter((p) => p.id !== id));
    setTotal((t) => Math.max(0, t - 1));
  };

  return {
    projects,
    total,
    loading,
    error,
    fetchProjects,
    createProject,
    updateProject,
    deleteProject,
  };
}

export default useProjects;
