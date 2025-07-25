/**
 * Copyright 2025 © BeeAI a Series of LF Projects, LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import humanizeDuration from 'humanize-duration';
import JSON5 from 'json5';
import { v4 as uuid } from 'uuid';

import { isNotNull } from '#utils/helpers.ts';
import { toMarkdownCitation, toMarkdownImage } from '#utils/markdown.ts';

import type { Artifact, Message, MessagePart } from './api/types';
import {
  type AgentMessage,
  type ChatMessage,
  type CitationTransform,
  type MessageContentTransform,
  MessageContentTransformType,
  type UserMessage,
} from './chat/types';
import type { UploadFileResponse } from './files/api/types';
import type { FileEntity } from './files/types';
import { getFileContentUrl } from './files/utils';
import type { SourceReference } from './sources/api/types';
import { Role } from './types';

humanizeDuration.languages.shortEn = {
  h: () => 'h',
  m: () => 'min',
  s: () => 's',
};

export function runDuration(ms: number) {
  const duration = humanizeDuration(ms, {
    units: ['h', 'm', 's'],
    round: true,
    delimiter: ' ',
    spacer: '',
    language: 'shortEn',
  });

  return duration;
}

export function createMessagePart({
  content,
  content_encoding = 'plain',
  content_type = 'text/plain',
  content_url,
  name,
}: Partial<Exclude<MessagePart, 'role'>>): MessagePart {
  return {
    content,
    content_encoding,
    content_type,
    content_url,
    name,
    role: Role.User,
  };
}

export function createFileMessageParts(files: (UploadFileResponse & { type: string })[]) {
  const messageParts = files.map(({ id, filename, type }) =>
    createMessagePart({
      content_url: getFileContentUrl({ id, addBase: true }),
      content_type: type,
      name: filename,
    }),
  );

  return messageParts;
}

export function createImageTransform({
  imageUrl,
  insertAt,
}: {
  imageUrl: string;
  insertAt: number;
}): MessageContentTransform {
  const startIndex = insertAt;

  return {
    key: uuid(),
    kind: MessageContentTransformType.Image,
    startIndex,
    apply: ({ content, offset }) => {
      const adjustedStartIndex = startIndex + offset;
      const before = content.slice(0, adjustedStartIndex);
      const after = content.slice(adjustedStartIndex);

      return `${before}${toMarkdownImage(imageUrl)}${after}`;
    },
  };
}

export function createCitationTransform({ source }: { source: SourceReference }): CitationTransform {
  const { startIndex, endIndex } = source;

  return {
    key: uuid(),
    kind: MessageContentTransformType.Citation,
    startIndex,
    sources: [source],
    apply: function ({ content, offset }) {
      const adjustedStartIndex = startIndex + offset;
      const adjustedEndIndex = endIndex + offset;
      const before = content.slice(0, adjustedStartIndex);
      const text = content.slice(adjustedStartIndex, adjustedEndIndex);
      const after = content.slice(adjustedEndIndex);

      return `${before}${toMarkdownCitation({ text, sources: this.sources })}${after}`;
    },
  };
}

export function applyContentTransforms({
  rawContent,
  transforms,
}: {
  rawContent: string;
  transforms: MessageContentTransform[];
}): string {
  let offset = 0;

  const transformedContent = transforms
    .sort((a, b) => a.startIndex - b.startIndex)
    .reduce((content, transform) => {
      const newContent = transform.apply({ content, offset });
      offset += newContent.length - content.length;

      return newContent;
    }, rawContent);

  return transformedContent;
}

export function isArtifactPart(part: MessagePart): part is Artifact {
  return typeof part.name === 'string';
}

export function extractOutput(messages: Message[]) {
  const output = messages
    .flatMap(({ parts }) => parts)
    .map(({ content }) => content)
    .filter(isNotNull)
    .join('');

  return output;
}

export function extractValidUploadFiles(files: FileEntity[]) {
  const uploadFiles = files
    .map(({ uploadFile, originalFile: { type } }) => (uploadFile ? { ...uploadFile, type } : null))
    .filter(isNotNull);

  return uploadFiles;
}

export function mapToMessageFiles(uploadFiles: UploadFileResponse[]) {
  return uploadFiles.map(({ id, filename }) => ({ key: id, filename, href: getFileContentUrl({ id }) }));
}

export const parseJsonLikeString = (string: string): unknown | string => {
  try {
    const json = JSON5.parse(string);

    return json;
  } catch {
    return string;
  }
};

export function isAgentMessage(message: ChatMessage): message is AgentMessage {
  return message.role === Role.Agent || message.role.startsWith(`${Role.Agent}/`);
}

export function isUserMessage(message: ChatMessage): message is UserMessage {
  return message.role === Role.User;
}
