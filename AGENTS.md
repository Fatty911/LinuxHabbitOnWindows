

## Git 提交作者身份规则（Fatty911 全局要求，2026-08-04）

本仓库所有 Git 提交必须遵守以下作者命名规则：

1. **全局兜底身份**：`Fatty911 <xuerui911@gmail.com>`。禁止使用 `bot@users.noreply.github.com` 邮箱（该邮箱关联 GitHub 用户名 `bot`，网页端会显示纯 `bot`）。
2. **Agent 工具显式提交**：使用动态格式 `<实际工具名>-<实际模型>`。工具名 = 实际执行提交的 Agent 工具（如 hermes-agent / codex / opencode / openclaw / mimocode / qoder）。模型名 = 本次实际处理会话的模型 ID 的小写紧凑写法（如 GLM-5.2 → `glm5.2`、GPT-5.6-Sol → `gpt5.6sol`、Kimi-K3 → `kimi-k3`、DeepSeek-V4-Flash → `deepseek-v4-flash`）。示例：`opencode-kimi-k3`、`hermes-agent-glm5.2`、`codex-gpt5.5`。
3. 禁止纯 `bot` 名称或系统 bot 身份冒充源码/文档提交；`github-actions[bot]` 仅限数据/进度自动提交。
4. 邮箱一律使用 `xuerui911@gmail.com`。
