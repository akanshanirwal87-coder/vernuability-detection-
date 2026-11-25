import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { ProjectService } from '../services/projectService';
import { getScans } from '../services/scanService';
import type { Project } from '../types/project';
import type { ScanHistoryItem } from '../types/scan';
import { RecentScans } from '../components/dashboard/RecentScans';
import { CardSkeleton, TableSkeleton } from '../components/common/Loader';
import { formatDate } from '../utils/formatDate';
import {
  FolderGit2,
  GitBranch,
  Terminal,
  ExternalLink,
  ArrowLeft,
  Calendar,
  Code2,
} from 'lucide-react';
import { toast } from 'sonner';

export const ProjectDetails: React.FC = () => {
  const { projectId } = useParams<{ projectId: string }>();
  const navigate = useNavigate();

  const [project, setProject] = useState<Project | null>(null);
  const [scans, setScans] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    if (!projectId) return;

    const loadData = async () => {
      setLoading(true);
      try {
        const [proj, allScans] = await Promise.all([
          ProjectService.getProject(projectId),
          getScans(),
        ]);
        setProject(proj);
        // Filter scans associated with this project name or id
        const filtered = allScans.filter(
          (s) => s.projectName === proj.name || (s as any).projectId === proj.id
        );
        setScans(filtered);
      } catch (err: any) {
        toast.error('Failed to load project details');
      } finally {
        setLoading(false);
      }
    };

    loadData();
  }, [projectId]);

  if (loading) {
    return (
      <div className="space-y-6">
        <CardSkeleton rows={3} />
        <TableSkeleton rows={4} />
      </div>
    );
  }

  if (!project) {
    return (
      <div className="flex flex-col items-center justify-center p-12 text-center">
        <FolderGit2 className="h-12 w-12 text-slate-600 mb-3" />
        <h2 className="text-xl font-bold text-white">Project Not Found</h2>
        <p className="mt-2 text-sm text-slate-400">The requested project does not exist or was deleted.</p>
        <Link
          to="/projects"
          className="mt-6 inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-xs font-semibold text-white hover:bg-indigo-500"
        >
          <ArrowLeft className="h-4 w-4" />
          <span>Back to Projects</span>
        </Link>
      </div>
    );
  }

  const totalFindings = scans.reduce((acc, s) => acc + (s.totalFindings || 0), 0);
  const criticalFindings = scans.filter((s) => s.highestSeverity === 'CRITICAL').length;

  return (
    <div className="space-y-6">
      {/* Back button */}
      <div>
        <Link
          to="/projects"
          className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          <span>Back to Projects</span>
        </Link>
      </div>

      {/* Project Overview Card */}
      <div className="rounded-2xl border border-slate-800 bg-[#111827] p-6 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start gap-4">
            <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 shrink-0">
              <FolderGit2 className="h-7 w-7" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">{project.name}</h1>
              <p className="text-xs text-slate-400 mt-1 max-w-2xl">
                {project.description || 'No description provided.'}
              </p>
              <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400 mt-3">
                <span className="flex items-center gap-1 font-mono text-cyan-400">
                  <Code2 className="h-3.5 w-3.5" />
                  {project.language?.toUpperCase() || 'PYTHON'}
                </span>
                <span>•</span>
                <span className="flex items-center gap-1 font-mono">
                  <GitBranch className="h-3.5 w-3.5 text-indigo-400" />
                  {project.default_branch}
                </span>
                <span>•</span>
                <span className="flex items-center gap-1">
                  <Calendar className="h-3.5 w-3.5 text-slate-500" />
                  {formatDate(project.created_at)}
                </span>
              </div>
            </div>
          </div>

          <button
            onClick={() => navigate('/scan', { state: { projectId: project.id, projectName: project.name } })}
            className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2.5 text-xs font-semibold text-white shadow-lg shadow-indigo-600/20 hover:bg-indigo-500 transition active:scale-95 shrink-0"
          >
            <Terminal className="h-4 w-4" />
            <span>Scan Project</span>
          </button>
        </div>

        {project.repository_url && (
          <div className="mt-4 pt-4 border-t border-slate-800 flex items-center gap-2 text-xs text-cyan-400">
            <ExternalLink className="h-3.5 w-3.5" />
            <a href={project.repository_url} target="_blank" rel="noopener noreferrer" className="hover:underline">
              {project.repository_url}
            </a>
          </div>
        )}
      </div>

      {/* Project Statistics */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl border border-slate-800 bg-[#111827]">
          <span className="text-xs font-medium text-slate-400">Total Scans Run</span>
          <h3 className="text-2xl font-bold text-white mt-1">{scans.length}</h3>
          <span className="text-[11px] text-cyan-400 font-mono">AST & SCA</span>
        </div>
        <div className="p-4 rounded-xl border border-slate-800 bg-[#111827]">
          <span className="text-xs font-medium text-slate-400">Total Findings</span>
          <h3 className="text-2xl font-bold text-white mt-1">{totalFindings}</h3>
          <span className="text-[11px] text-amber-400 font-mono">Detected Issues</span>
        </div>
        <div className="p-4 rounded-xl border border-slate-800 bg-[#111827]">
          <span className="text-xs font-medium text-slate-400">Critical Severities</span>
          <h3 className="text-2xl font-bold text-red-400 mt-1">{criticalFindings}</h3>
          <span className="text-[11px] text-red-400 font-mono">Requires Remediation</span>
        </div>
      </div>

      {/* Scan History for this Project */}
      <RecentScans scans={scans} />
    </div>
  );
};

export default ProjectDetails;
