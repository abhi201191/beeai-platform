/**
 * Copyright 2025 © BeeAI a Series of LF Projects, LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { parseNav } from '#modules/nav/parseNav.ts';

export const APP_NAME = process.env.NEXT_PUBLIC_APP_NAME ?? 'BeeAI';

export const APP_FAVICON_SVG = process.env.NEXT_PUBLIC_APP_FAVICON_SVG ?? '/bee.svg';

export const PHOENIX_SERVER_TARGET = process.env.NEXT_PUBLIC_PHOENIX_SERVER_TARGET ?? 'http://localhost:31606';

export const NAV_ITEMS = parseNav(process.env.NEXT_PUBLIC_NAV_ITEMS);

export const API_URL = process.env.API_URL;

export const PROD_MODE = process.env.NODE_ENV === 'production';

export const GITHUB_REPO_LINK = 'https://github.com/i-am-bee/beeai';

export const FRAMEWORK_GITHUB_REPO_LINK = 'https://github.com/i-am-bee/beeai-framework';

export const DISCORD_LINK = 'https://discord.gg/NradeA6ZNF';

export const YOUTUBE_LINK = 'https://www.youtube.com/@BeeAIAgents';

export const BLUESKY_LINK = 'https://bsky.app/profile/beeaiagents.bsky.social';

export const GET_SUPPORT_LINK = 'https://github.com/i-am-bee/beeai-platform/discussions/categories/q-a';

export const DOCUMENTATION_LINK = 'https://docs.beeai.dev';

export const ACP_DOCUMENTATION_LINK = 'https://agentcommunicationprotocol.dev/introduction/welcome';

export const BEE_AI_FRAMEWORK_TAG = 'BeeAI';

export const INSTALL_BEEAI = 'uv tool install beeai-cli';

export const TRY_LOCALLY_LINK = `${DOCUMENTATION_LINK}/introduction/quickstart`;

export const TRACEABILITY_LINK = `${DOCUMENTATION_LINK}/observability/agents-traceability`;

export const RUN_LINK = `${DOCUMENTATION_LINK}/how-to/run-agents`;

export const COMPOSE_LINK = `${DOCUMENTATION_LINK}/how-to/compose-agents`;

export const LF_PROJECTS_LINK = 'https://lfprojects.org/';

export const AGENT_DISPLAY_MODEL_TEMP = 'granite-3.3-8b-instruct';
