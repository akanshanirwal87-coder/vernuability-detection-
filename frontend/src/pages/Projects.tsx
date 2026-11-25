import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useProjects } from '../hooks/useProjects';
import { Modal } from '../components/common/Modal';
import { CardSkeleton, TableSkeleton } from '../components/common/Loader';
import { formatDate } from '../utils/formatDate';
import {
  FolderGit2,
  Plus,
  Search,
  ExternalLink,
  Trash2,
  Terminal,
  GitBranch,
  Shield,
  Layers,
} from 'lucide-react';
import { toast } from 'sonner';

export const Projects: React.FC = () => {
  const navigate = useNavigate();
  const { projects, total, loading, fetchProjects, createProject, deleteProject } = useProjects();
  const [searchTerm, setSearchTerm] = useState('');
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [deleteId, setDeleteId] = useState<string | null>(null);

  // Form State
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [repositoryUrl, setRepositoryUrl] = useState('');
  const [defaultBranch, setDefaultBranch] = useState('main');
  const [language, setLanguage] = useState('python');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    fetchProjects({ search: searchTerm });
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      toast.error('Project name is required');
      return;
    }
    setIsSubmitting(true);
    try {
      await createProject({
        name: name.trim(),
        description: description.trim() || undefined,
        repository_url: repositoryUrl.trim() || undefined,
        default_branch: defaultBranch.trim() || 'main',
        language,
      });
      toast.success('Project created successfully');
      setIsCreateOpen(false);
      setName('');
      setDescription('');
      setRepositoryUrl('');
    } catch (err: any) {
      toast.error(err.response?.data?.message || err.message || 'Failed to create project');
    } finally {
      setIsSubmitting(false);
    }
  };

  const confirmDelete = async () => {
    if (!deleteId) return;
    try {
      await deleteProject(deleteId);
      toast.success('Project removed');
      setDeleteId(null);
    } catch (err: any) {
      toast.error('Failed to delete project');
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Project Management</h1>
          <p className="text-xs text-slate-400 mt-1">
            Organize repositories, manage continuous SAST scanning, and track vulnerability remediation over time.
          </p>
        </div>
        <button
          onClick={() => setIsCreateOpen(true)}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-lg shadow-indigo-600/20 transition active:scale-95 w-fit"
        >
          <Plus className="w-4 h-4" />
          <span>New Project</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-3">
        <form onSubmit={handleSearch} className="relative flex-1">
          <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search projects by name..."
            className="w-full rounded-lg border border-slate-700 bg-slate-900/80 py-2 pl-10 pr-4 text-xs text-white placeholder-slate-500 transition focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          />
        </form>
      </div>

      {/* Content */}
      {loading ? (
        <TableSkeleton rows={4} cols={5} />
      ) : projects.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-2xl border border-slate-800 bg-[#111827] p-12 text-center shadow-lg">
          <div className="mb-4 rounded-2xl bg-indigo-500/10 p-5 ring-1 ring-indigo-500/30">
            <FolderGit2 className="h-10 w-10 text-indigo-400" />
          </div>
          <h2 className="text-xl font-bold text-white">No Projects Registered</h2>
          <p className="mt-2 max-w-md text-sm text-slate-400">
            Create a project to connect your repository and begin tracking security audits and automated fixes across commits.
          </p>
          <button
            onClick={() => setIsCreateOpen(true)}
            className="mt-6 inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-5 py-2.5 text-sm font-semibold text-white shadow-lg shadow-indigo-600/30 transition hover:bg-indigo-500"
          >
            <Plus className="h-4 w-4" />
            <span>Create First Project</span>
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {projects.map((project) => (
            <div
              key={project.id}
              className="group flex flex-col justify-between rounded-xl border border-slate-800 bg-[#111827] p-5 transition-all hover:border-slate-700 hover:shadow-xl hover:shadow-indigo-950/20"
            >
              <div>
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center gap-2.5">
                    <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
                      <FolderGit2 className="h-5 w-5" />
                    </div>
                    <div>
                      <Link
                        to={`/projects/${project.id}`}
                        className="font-bold text-white hover:text-indigo-400 transition-colors"
                      >
                        {project.name}
                      </Link>
                      <div className="flex items-center gap-2 text-[11px] text-slate-400 mt-0.5">
                        <span className="font-mono">{project.language?.toUpperCase() || 'PYTHON'}</span>
                        <span>•</span>
                        <span className="flex items-center gap-1 font-mono">
                          <GitBranch className="h-3 w-3" />
                          {project.default_branch}
                        </span>
                      </div>
                    </div>
                  </div>
                  <button
                    onClick={() => setDeleteId(project.id)}
                    className="p-1.5 text-slate-500 hover:text-red-400 hover:bg-red-500/10 rounded transition-colors"
                    title="Delete project"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>

                {project.description && (
                  <p className="mt-3 text-xs text-slate-400 line-clamp-2 leading-relaxed">
                    {project.description}
                  </p>
                )}

                {project.repository_url && (
                  <div className="mt-3 flex items-center gap-1 text-[11px] text-cyan-400 hover:underline">
                    <ExternalLink className="h-3 w-3" />
                    <a href={project.repository_url} target="_blank" rel="noopener noreferrer" className="truncate">
                      {project.repository_url}
                    </a>
                  </div>
                )}
              </div>

              <div className="mt-5 pt-4 border-t border-slate-800/80 flex items-center justify-between text-xs">
                <span className="text-slate-500 text-[11px]">
                  Created {formatDate(project.created_at)}
                </span>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => navigate('/scan', { state: { projectId: project.id, projectName: project.name } })}
                    className="flex items-center gap-1 px-2.5 py-1.5 rounded bg-indigo-600/20 hover:bg-indigo-600/40 text-indigo-300 border border-indigo-500/30 font-medium transition"
                  >
                    <Terminal className="h-3.5 w-3.5" />
                    <span>Scan</span>
                  </button>
                  <Link
                    to={`/projects/${project.id}`}
                    className="px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium transition"
                  >
                    Details
                  </Link>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create Project Modal */}
      <Modal isOpen={isCreateOpen} onClose={() => setIsCreateOpen(false)} title="Create New Security Project">
        <form onSubmit={handleCreate} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300">
              Project Name *
            </label>
            <input
              type="text"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. core-auth-service"
              className="mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-900/80 px-3 py-2 text-sm text-white placeholder-slate-500 transition focus:border-indigo-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300">
              Description
            </label>
            <textarea
              rows={2}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Brief summary of repository and security boundaries..."
              className="mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-900/80 px-3 py-2 text-sm text-white placeholder-slate-500 transition focus:border-indigo-500 focus:outline-none"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300">
                Primary Language
              </label>
              <select
                value={language}
                onChange={(e) => setLanguage(e.target.value)}
                className="mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-900/80 px-3 py-2 text-sm text-white transition focus:border-indigo-500 focus:outline-none"
              >
                <option value="python">Python (AST + Taint)</option>
                <option value="javascript">JavaScript / Node</option>
                <option value="typescript">TypeScript</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300">
                Default Branch
              </label>
              <input
                type="text"
                value={defaultBranch}
                onChange={(e) => setDefaultBranch(e.target.value)}
                placeholder="main"
                className="mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-900/80 px-3 py-2 text-sm text-white placeholder-slate-500 transition focus:border-indigo-500 focus:outline-none"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300">
              Git Repository URL
            </label>
            <input
              type="url"
              value={repositoryUrl}
              onChange={(e) => setRepositoryUrl(e.target.value)}
              placeholder="https://github.com/org/repo"
              className="mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-900/80 px-3 py-2 text-sm text-white placeholder-slate-500 transition focus:border-indigo-500 focus:outline-none"
            />
          </div>

          <div className="pt-2 flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setIsCreateOpen(false)}
              className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 text-xs font-medium transition"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-lg shadow-indigo-600/30 transition disabled:opacity-50"
            >
              {isSubmitting ? 'Creating...' : 'Create Project'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal isOpen={!!deleteId} onClose={() => setDeleteId(null)} title="Delete Project">
        <div className="space-y-4">
          <p className="text-sm text-slate-300">
            Are you sure you want to delete this project? All associated scan records will remain archived, but the project association will be removed.
          </p>
          <div className="flex justify-end gap-2 pt-2">
            <button
              onClick={() => setDeleteId(null)}
              className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 text-xs font-medium transition"
            >
              Cancel
            </button>
            <button
              onClick={confirmDelete}
              className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-semibold transition"
            >
              Delete Project
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
};

export default Projects;
