# O que é isto, e a quem serve

Uma apresentação em linguagem corrente do portal comercial `manager2`, escrita
para quem não vai ler o código: o responsável que decide se o adopta, e o
comercial que o explica.

Há dois destinatários ao longo de todo o documento, e são mantidos separados
porque querem coisas diferentes:

- **O cliente** — o fabricante ou transformador de vidro que *opera* o portal.
- **O consumidor** — o vidraceiro, o instalador de janelas, a carpintaria ou o
  empreiteiro que *compra através* dele.

O sistema só funciona se for melhor para ambos. Um portal que poupa trabalho ao
fabricante empurrando-o para o instalador é abandonado num mês; os instaladores
voltam simplesmente a telefonar.

---

## 1. O problema que resolve

Os vidros duplos feitos por medida são vendidos de uma forma que praticamente não
mudou em trinta anos.

O instalador mede um vão em obra. Telefona ou envia por e-mail uma lista de
medidas — às vezes uma fotografia de uma folha manuscrita. Alguém no escritório
orça à mão a partir de uma tabela de preços, lança tudo numa folha de cálculo, e
devolve o orçamento por e-mail. Dois dias depois o instalador aceita, talvez com
uma alteração. A encomenda é redigitada para produção. A data de entrega é
combinada verbalmente. A factura é emitida à parte, a partir de outros números.

Cada passo é uma oportunidade de erro de transcrição, e neste produto um erro de
transcrição é caro: uma unidade cortada a 1197 mm em vez de 1179 mm não se vende
a mais ninguém. É sucata, mais uma refabricação, mais uma obra atrasada.

**Os custos que o fabricante suporta na realidade:**

| Custo | De onde vem |
|---|---|
| Mão de obra de orçamentação | Horas por dia a orçar listas à mão |
| Refabricações e sucata | Medidas e especificações transcritas à mão, duas vezes |
| Aceitação lenta | Os orçamentos ficam em caixas de correio; a encomenda chega tarde para o plano de corte |
| Produção não planeada | As encomendas chegam como um monte, não como um plano |
| Facturação tardia | A facturação é uma passagem manual separada, e o dinheiro entra mais tarde |
| Risco de crédito não avaliado | As condições são definidas por relação e memória, não pelo histórico de pagamento |
| Falhas de rastreabilidade | Obrigações de marcação CE cumpridas com arquivo em papel (ver §5) |

**Os custos que o instalador suporta:** esperar por um preço quando precisa de
orçamentar a um cliente hoje; não saber o que custa uma alteração de
especificação até alguém lhe responder; não ter visibilidade sobre se o vidro
chega terça ou quinta, numa obra onde já marcou um montador e possivelmente uma
grua.

---

## 2. O que ganha o consumidor

**Um preço imediato, às suas próprias condições contratadas.** Introduz largura,
altura, quantidade e especificação; obtém o preço unitário, o total da linha e o
prazo de fabrico no ecrã. Sem esperas, sem telefonemas e — a parte que os
instaladores mais valorizam — pode orçamentar *estando em casa do cliente*.

**O custo de uma alteração de especificação, antes de se comprometer.** Trocar
vidro incolor por vidro de controlo solar, acrescentar temperado, passar de duplo
a triplo: o preço, o valor U e o prazo actualizam-se. Hoje isso são três e-mails e
um dia de atraso. E também vende melhor vidro, porque o instalador vê que a
melhoria custa 14 €/m² em vez de presumir que é caro.

**As medidas registadas uma vez, por quem as tirou.** Quem digita as dimensões
assume o erro. Quando é o instalador a introduzi-las e a confirmá-las no ecrã, a
discussão sobre quem disse 1179 deixa de existir. As medidas ficam na encomenda e
reaparecem na documentação e na etiqueta.

**Locais de entrega guardados.** Um cliente habitual que entrega sempre nas
mesmas três obras não volta a escrever a morada, o contacto local e o "cais de
carga nas traseiras, precisa de plataforma elevatória, toque à campainha".

**Uma janela de entrega escolhida por ele, e uma hora firme quando a encomenda é
aceite.** O vidro exige alguém presente, com o equipamento de manuseamento certo.
Uma janela escolhida em vez de anunciada vale dinheiro real a quem escala
montadores.

**Repetir e reencomendar.** Quase todo o trabalho de vidraçaria é repetitivo.
Reencomendar uma linha anterior — mesma especificação, medidas novas — leva
segundos.

**Um único sítio para perguntar.** Um fio de mensagens associado à encomenda, para
que "isto já saiu?" não obrigue a descobrir a pessoa certa. Os funcionários de
apoio podem ler estas mensagens, e a interface di-lo.

**A documentação dele, quando quiser.** Facturas, guias de transporte e a
declaração de desempenho das unidades fornecidas — sem ter de a pedir por e-mail.

---

## 3. O que ganha o cliente

**Mão de obra de orçamentação praticamente eliminada.** O preço é a tabela,
aplicada de forma consistente, às três da manhã se for a essa hora que o
instalador está a trabalhar.

**Encomendas que chegam como dados de produção.** Dimensões, composição,
revestimento, cor e opções chegam estruturadas e validadas contra o que a
fábrica consegue realmente produzir — dimensão máxima de pano, área mínima
facturável, incrementos de medida. Uma encomenda impossível de produzir é
recusada na entrada, em vez de ser descoberta na mesa de corte.

**Uma fila em vez de um monte.** As encomendas ordenam-se por data prometida,
categoria do cliente e estado de pagamento. Aceitar, recusar, definir data de
satisfação, escolher o meio de expedição.

**Facturas emitidas a partir da encomenda, corretamente e de imediato.**
Sequenciais, sem lacunas, encadeadas por *hash*, com o número de contribuinte
validado e o tratamento fiscal certo — incluindo a autoliquidação nas transmissões
intracomunitárias, que é aquela que custa dinheiro quando está errada. Facturar no
dia da expedição em vez de ao fim do mês antecipa a tesouraria em duas a três
semanas, em média.

**Risco de crédito avaliado com base em factos.** O comportamento de pagamento —
dias de atraso, dias em dívida, saldo vencido, pagamentos falhados — produz uma
pontuação e uma recomendação. É explicável, pode ser sobreposta por uma pessoa, e
o raciocínio fica registado. Substitui o "acho que estes costumam ser certos".

**Margem visível por encomenda, não por mês.** O custo é registado em cada linha
no momento da venda, pelo que o fabricante consegue ver que são as unidades
fumadas que estão a sustentar o mês e que o vidro duplo incolor mal paga o posto
de produção que ocupa.

**Capacidade contra procura.** Metros quadrados encomendados por semana contra a
capacidade da linha: o número que diz ao responsável de produção se autoriza
horas extraordinárias na quarta-feira ou aceita uma encomenda urgente na quinta.

**Rastreabilidade que já é uma obrigação legal, obtida como subproduto.** Ver §5.

---

## 4. Porque é que o vidro por medida encaixa particularmente bem

A maioria dos portais de encomenda B2B pressupõe produtos em stock: uma
referência, uma quantidade, um preço. Os vidros duplos quebram esse pressuposto
de formas que tornam um portal genérico inútil — e um portal desenhado para o
efeito invulgarmente valioso.

**Configurado, não escolhido.** Uma unidade é uma composição (`4-16Ar-4`), um
revestimento, uma cor, um tipo de perfil separador e duas dimensões em
milímetros. Não há referência, e não há stock — apenas prazo de fabrico e
capacidade.

**Preço por área, com um mínimo.** As tabelas são por metro quadrado com uma área
mínima facturável por unidade, pelo que uma unidade de 300 × 400 mm custa o mesmo
que uma de 600 × 900 mm. Os clientes questionam isto constantemente. Um
configurador que mostra a área *facturável* ao lado da área real responde antes de
o telefone tocar.

**Os valores de desempenho fazem parte do produto.** Ug, factor solar,
transmissão luminosa e Rw são o que o cliente está de facto a comprar, e são o que
o projectista especificou. Mostrá-los a mudar à medida que a especificação muda
transforma a folha de encomenda numa ferramenta de especificação — o que é uma
vantagem comercial concreta face a um concorrente que envia uma tabela em PDF.

**Feito por medida significa não devolvível.** Uma unidade com a medida errada não
tem valor de revenda. Isso aumenta o risco tanto na exactidão dos dados como nas
condições de pagamento: é por isso que os sinais em trabalho por medida e o
pré-pagamento de contas não verificadas são normais no sector, e é por isso que o
portal impõe um limite de encomenda até a conta estar verificada.

**A entrega é um problema de manuseamento.** Cavaletes, bastidores, plataforma
elevatória, manuseamento a dois, vidro acima de determinada área a exigir
equipamento. As instruções de entrega não são aqui um detalhe simpático.

**As refabricações são um fluxo de trabalho real.** Quebra no transporte, uma
unidade com defeito, um erro de medição em obra — cada caso precisa de ser
registado contra o original, com a responsabilidade atribuída, porque é isso que
determina quem paga.

> **Nota para a implementação:** o esquema tal como está escrito pressupõe
> referências em stock. A extensão para produto por medida está em
> `db/schema-glazing.sql` — dimensões e especificação por unidade nas linhas de
> encomenda, preço por área com mínimo, valores de desempenho, capacidade de
> produção e registo de refabricações. Esse ficheiro é a camada de adaptação; as
> camadas de cifra, facturação, auditoria e RGPD não precisam de alterações.

---

## 5. O argumento regulamentar — e é um argumento forte

Vale a pena ler esta secção com atenção, porque transforma uma obrigação
burocrática na razão para adoptar o sistema.

Os vidros isolantes são **produtos de construção**. A EN 1279-5 é a norma
harmonizada de produto, e aplica-se a marcação CE ao abrigo do Regulamento dos
Produtos de Construção da UE. Daí resultam três deveres:

**Uma Declaração de Desempenho do produto** (art. 4.º do RPC). Exigida quando se
aplica uma norma harmonizada. Existe uma derrogação restrita no art. 5.º para
produtos fabricados individualmente, e saber se os vidros por medida cabem nela é
uma questão para um organismo certificador, não para este documento — a maioria
das unidades por medida fabricadas em série não cabe.

**Dez anos de registos** (art. 11.º, n.º 2, do RPC). A Declaração de Desempenho e
a documentação técnica de suporte devem ser conservadas durante dez anos após o
produto ser colocado no mercado.

**Rastreabilidade, incluindo a quem vendeu** (arts. 11.º, n.º 4, e 16.º do RPC).
As unidades têm de ostentar identificação de tipo, lote ou número de série. E
durante dez anos, quando solicitado, um operador económico tem de conseguir
identificar tanto os fornecedores que lhe forneceram como **os clientes a quem
forneceu produto**.

É esta última obrigação que interessa. Um fabricante de vidros com marcação CE
está sujeito ao **dever legal de saber quem são os seus clientes, e de o conseguir
provar uma década mais tarde.** Qualquer sistema de encomendas construído em torno
de compradores anónimos ou pseudónimos não é apenas má prática neste sector — é
inutilizável, porque não consegue responder à pergunta que uma autoridade de
fiscalização do mercado tem o direito de fazer.

Assim, o desenho do portal centrado na identidade não é atrito acrescentado sem
motivo. Produz, como subproduto de receber encomendas normalmente:

- uma identidade jurídica verificada para cada conta comercial, com o número de
  contribuinte validado no VIES e a referência da consulta guardada como prova;
- dez anos de registos de transacções conservados, já alinhados com os dez anos de
  conservação fiscal de que a mesma empresa precisa de qualquer forma;
- a metade do registo de cadeia de fornecimento do art. 16.º relativa a clientes,
  consultável em segundos em vez de reconstruída a partir de arquivos;
- um registo de auditoria de quem acedeu a quê, separadamente útil quando um
  titular de dados pergunta.

**Duas ressalvas, ditas com clareza.** Primeira: um Regulamento dos Produtos de
Construção revisto (Regulamento (UE) 2024/3110) substitui o 305/2011 num
calendário faseado; os deveres de documentação e rastreabilidade não desaparecem,
e o calendário de transição da sua família de produtos deve ser confirmado com o
organismo certificador. Segunda: nada disto faz do software um substituto de
software de facturação certificado pela AT em Portugal, nem do controlo de
produção em fábrica da EN 1279 — ver `docs/SECURITY.md` §4 e `docs/GDPR.md` §9.

---

## 6. E o lado da privacidade, com honestidade

O sistema cifra aquilo que vale a pena cifrar — moradas de obra, nomes de
contacto, números de telefone, instruções de entrega, corpo das mensagens — com
cifra autenticada linha a linha, pelo que uma cópia de segurança roubada ou uma
réplica exposta não devolvem nada legível.

**Não** cifra denominações sociais, números de contribuinte nem sedes, porque são
dados públicos de registo comercial e cifrá-los quebraria as validações no VIES e
a emissão de facturas sem proteger nada.

Registra quem decifrou dados pessoais, quando e porquê — porque cifra sem registo
de acessos é opacidade e não privacidade, inclusive perante as pessoas a quem os
dados pertencem. Quando um titular pergunta, a exportação diz-lhe qual a *função*
de quem consultou os seus dados e com que motivo.

E consegue responder corretamente a um pedido de apagamento, o que passa
sobretudo por saber o que não pode apagar: as facturas ficam, porque a lei fiscal
o exige e a identidade do cliente é conteúdo obrigatório do documento. A recusa é
fundamentada e registada em vez de contornada.

Nada disto torna uma organização conforme com o RGPD por si só — isso exige
também uma política de privacidade, contratos de subcontratação e alguém
responsável. A secção §9 de `docs/GDPR.md` enumera o que falta.

---

## 7. O que está feito, e o que não está

**A funcionar e testado** (40 verificações de criptografia, 81 verificações de
integração contra um MariaDB real):

- Esquema de base de dados, incluindo o registo de actividades de tratamento
- Cifra a nível de campo com rotação de chaves e índices cegos pesquisáveis
- Credenciais com Argon2id
- Adesão por convite com verificação da empresa e validação de NIF
- Tratamento de *webhooks* de pagamento: verificação de assinatura, protecção
  contra reenvio, idempotência, reconciliação de valores
- Facturação: numeração sequencial sem lacunas, cadeia inviolável
- Mensagens de encomenda, cifradas em repouso
- Avaliação de crédito com revisão humana
- Acesso, portabilidade e apagamento; expurgo por prazo de conservação
- Registo de auditoria só de acrescento, com detecção de manipulação
- Checkout para telemóvel, modo escuro, PWA instalável

**Ainda não feito:**

- Controladores de sessão e autenticação (os componentes existem; a imposição não)
- **Delimitação por conta** — toda a consulta virada para o cliente tem de estar
  restringida à conta autenticada. É o ponto pendente mais importante.
- A interface do painel de gestão (a camada de dados e a ordenação da fila existem)
- Catálogo, carrinho e o configurador por medida como código de produção
- Facturas e guias em PDF; geração da Declaração de Desempenho
- Inscrição na autenticação de dois factores

Realisticamente, isto é uma base sólida com as partes difíceis e fáceis de errar
já feitas — cifra, pagamentos, facturação, conformidade — e o trabalho corrente de
aplicação web por fazer.

---

## 8. Apresentar a demonstração

O ficheiro `demo/index.html` é uma demonstração interactiva autónoma. Corre num
navegador sem servidor e sem instalação, pelo que funciona num portátil no
escritório de qualquer pessoa. Não precisa de rede para funcionar — sem ligação
recorre aos tipos de letra do sistema, pelo que se for apresentar num local sem
wifi vale a pena abri-la uma vez antes para os guardar em cache. Tem um selector
inglês/português.

**Percurso sugerido de cinco minutos, nesta ordem:**

1. **Abrir no configurador.** Alterar a altura. Deixá-los ver o preço, a área
   facturável e o corte transversal a mexer. Não dizer nada durante uns segundos —
   é este o momento que convence, e convence melhor sem narração.
2. **Mudar a cor para fumado cinza.** Apontar para o factor solar a descer e a
   transmissão luminosa a descer com ele. É esta a conversa de venda que os
   comerciais deles hoje têm mal, ao telefone.
3. **Acrescentar temperado.** Apontar para o prazo a passar de 5 para 7 dias.
   Perguntar quanto tempo levam hoje a dizer isso a um cliente.
4. **Ir à fila de encomendas.** Notar a encomenda sinalizada por exceder o limite
   de crédito, e a conta não verificada limitada a uma primeira encomenda de
   250 €. Perguntar como é tomada hoje essa decisão.
5. **Aceitar uma encomenda.** Mostrar o número de factura a aparecer de imediato.
6. **Ir aos números.** Margem por mês, e metros quadrados contra a capacidade da
   linha. Perguntar quando é que hoje descobrem que estão acima da capacidade.
7. **Fechar com a §5 deste documento** — o dever de dez anos de identificar os
   clientes. Se marcam CE, isto já é um problema deles, e o portal resolve-o como
   efeito secundário.

**Perguntas a esperar, com respostas honestas:**

- *"Aguenta a nossa tabela de preços?"* Sim — as tabelas são por metro quadrado
  por composição e categoria, com agravamentos por opção. Os números da
  demonstração são ilustrativos; os deles entram numa tabela.
- *"Integra com o nosso software de produção?"* Ainda não. Os dados da encomenda
  são estruturados e exportáveis; uma integração concreta é um projecto concreto.
- *"Quanto tempo para entrar em produção?"* Ser honesto — a base está feita, a
  camada de aplicação web não. Dimensionar isso a sério em vez de adivinhar na
  reunião.
- *"Os nossos dados estão seguros?"* Responder com o registo de acessos, não com o
  nome da cifra. Aos responsáveis interessa poder ver quem consultou o quê.
- *"E optimização de corte?"* Fora do âmbito, e dizê-lo. A optimização de corte e
  aproveitamento é um domínio especializado, e finge-lo faz perder credibilidade
  imediata junto de um responsável de produção.

**Não afirmar** que o sistema está certificado para o RGPD, que a facturação está
certificada pela AT, ou que a marcação CE está tratada de ponta a ponta. Cada uma
destas é uma limitação real enumerada acima, e um responsável de vidraçaria muito
provavelmente sabe mais sobre a EN 1279 do que quem apresenta.
