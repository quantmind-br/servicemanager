Permita que um administrador, na UI de administração de API keys (`/admin/api-keys`), exclua de vez chaves API geradas pelo sistema — tanto ativas quanto já revogadas.

Estado desejado:
- O admin consegue remover o registro da chave pela própria listagem da UI.
- Após a exclusão bem-sucedida, a chave some da lista e deixa de autenticar em qualquer uso (incluindo se ainda estivesse ativa).
- “Excluir” significa apagar o registro de vez (hard delete), não apenas revogar/marcar como revogada.

Limites:
- Escopo é a experiência do administrador na UI de API keys.
- A API HTTP `/api/v1` e o restante do produto permanecem intactos, salvo o que for estritamente necessário para essa exclusão pela UI funcionar.
- Não inclui exclusão em massa, novos papéis além de admin, nem outras telas.
