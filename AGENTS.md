

## Git 提交作者身份规则（Fatty911 全局要求，2026-08-04）

本仓库所有 Git 提交必须遵守以下作者命名规则：

1. **全局兜底身份**：`Fatty911 <<已批准的提交邮箱>>`。禁止使用 `<禁用的bot关联邮箱>` 邮箱（该邮箱关联 GitHub 用户名 `bot`，网页端会显示纯 `bot`）。
2. **Agent 工具显式提交**：使用动态格式 `<实际工具名>-<实际模型>`。工具名 = 实际执行提交的 Agent 工具（如 hermes-agent / codex / opencode / openclaw / mimocode / qoder）。模型名 = 本次实际处理会话的模型 ID 的小写紧凑写法（如 GLM-5.2 → `glm5.2`、GPT-5.6-Sol → `gpt5.6sol`、Kimi-K3 → `kimi-k3`、DeepSeek-V4-Flash → `deepseek-v4-flash`）。示例：`opencode-kimi-k3`、`hermes-agent-glm5.2`、`codex-gpt5.5`。
3. 禁止纯 `bot` 名称或系统 bot 身份冒充源码/文档提交；`github-actions[bot]` 仅限数据/进度自动提交。
4. 邮箱一律使用 `<已批准的提交邮箱>`。

> 隐私占位符说明：`<已批准的提交邮箱>`指用户已批准的实际提交邮箱，`<禁用的bot关联邮箱>`指被禁止、会关联纯 `bot` 作者身份的邮箱；二者都不是可直接填入 Git 的字面值。实际身份须从私有提交身份信息核对；未能确认时先暂停并请求确认，不猜测或新建身份。本说明不要求修改现有 Git 配置。

