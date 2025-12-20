# Extending Cartography's Resource Permission Relationships to Azure and GCP: My LFX Mentorship Journey

cartography cncf logo

Earlier this year (2025), I got the chance to jump into the Linux Foundation's LFX Mentorship program (Term 3) and work on Cartography—this super cool open-source security tool that throws all your technical assets and their relationships into a graph database. My mission? Extend Cartography's Resource Permission Relationships (RPR) feature (which was AWS-only at the time) to also work with Azure and Google Cloud Platform (GCP).

Using graphs to visualize security problems is honestly pretty powerful. The question we're trying to answer is simple but important: "who has permission to read and write to my sensitive data resources?" But here's the thing—most companies aren't just using AWS anymore. They're running stuff across AWS, Azure, and GCP, and trying to figure out permissions across all three is... well, it's a pain. That's where my project came in!

## What is Cartography ?

content

suzume gif

So Cartography is basically this Python tool that takes all your infrastructure, identities, and permissions and throws them into a Neo4j graph database. Instead of trying to piece together who can access what from a million different places, you can just query the graph. It's like having a map of your entire cloud infrastructure.

When I started my mentorship, Cartography already had AWS IAM Resource Permission Relationships working pretty well. You could ask questions like "who can read from my S3 buckets?" and get an answer without manually digging through IAM policies (which, let's be honest, can get pretty gnarly).

But here's the reality: most companies aren't living in a single-cloud world anymore. They've got stuff in AWS, Azure, and GCP, and trying to figure out permissions across all three is like trying to solve a puzzle where each piece is from a different puzzle box. The challenge was clear: make RPR work for Azure and GCP too, even though they each do permissions their own special way.

## What Resource Permission Relationships Do

Resource Permission Relationships (RPR) precompute permission mappings between cloud principals and resources, storing them as graph relationships. Instead of manually checking who can access what, you can query the graph with simple Cypher queries like "who can read my SQL Server?" and get instant answers.

**Why it's efficient:** Azure and GCP have hundreds of built-in roles and permissions. Calculating relationships for everything would be slow and wasteful. RPR lets you define exactly which permission relationships matter to you through simple YAML config files.

**How to use it:** Just add entries to your permission relationship YAML file. For example, to track who can administer Azure Key Vaults:

```yaml
- target_label: AzureKeyVault
  permissions:
  - Microsoft.KeyVault/vaults/delete
  - Microsoft.KeyVault/vaults/write
  relationship_name: CAN_ADMINISTER
```

This creates `(:EntraPrincipal)-[:CAN_ADMINISTER]->(:AzureKeyVault)` relationships in the graph, which you can query instantly. Use `--azure-permission-relationships-file` or `--gcp-permission-relationships-file` to specify your custom YAML file.

## Understanding Azure RBAC

image(gpt)

Azure decided to do things their own way (of course). Instead of AWS's IAM policies attached to principals, Azure uses Role-Based Access Control (RBAC). Here's how it works:

- **Principals** (EntraUser, EntraGroup, or EntraServicePrincipal—yeah, they renamed Azure AD to Entra, because why not?) get assigned **Azure Roles**
- Each role has a bunch of **permissions** (like `Microsoft.Sql/servers/read`)
- These role assignments are scoped to resources or resource groups
- Permissions are evaluated based on role assignments at the resource level

So to figure out if a user can read an Azure SQL Server, Cartography needs to:
1. Find all role assignments for that user (including groups they're in—because group expansion is fun)
2. Check if any of those roles have the `Microsoft.Sql/servers/read` permission
3. Make sure the role assignment scope actually matches the SQL Server resource
4. If everything checks out, create a `(:EntraUser)-[:CAN_READ]->(:AzureSQLServer)` relationship

Sounds straightforward, right? Well... mostly. The scope matching part got interesting, but we'll get to that.

### Why This Is Hard Without Cartography (The Manual Way Sucks)

So, you want to know who can read your Azure SQL Server. Without Cartography, here's what you'd have to do:

1. **Go to the Azure Portal** (or use Azure CLI/PowerShell)
2. **Find the SQL Server** you're interested in
3. **Check the Access Control (IAM) tab** to see role assignments
4. **For each role assignment**, look up what permissions that role has
5. **Check if the user is in any groups** that have role assignments (because group expansion is manual)
6. **Verify the scope** of each role assignment matches your resource
7. **Repeat for every resource** you care about
8. **Cross-reference with other resources** if you want to know "who has access to ALL my SQL servers?"

Oh, and if you want to do this across multiple subscriptions? Good luck. You're manually clicking through the Azure Portal for hours, or writing custom scripts that break every time Azure changes their API.

**The alternatives?** You could:
- Use Azure's built-in tools (Portal, CLI, PowerShell) - but they're resource-by-resource, not queryable
- Write custom scripts using Azure SDKs - but you're reinventing the wheel and maintaining it yourself
- Use third-party tools like CloudKnox or Ermetic - but they're expensive and don't give you the graph-based querying power

**Why Cartography is better:** All that data is already in the graph. You write one Cypher query, and boom—you have your answer. Plus, you can query across resources, across subscriptions, and even across cloud providers. Try doing that with the Azure Portal!

## Understanding GCP IAM

image(gpt)

GCP's IAM system is similar to Azure's RBAC:

- **Principals** (GCPUser, GCPServiceAccount, or GCPGroup) get **IAM Policy Bindings**
- Each binding has **roles** with **permissions** (like `storage.objects.get`)
- Permissions are evaluated at the project, folder, or organization level

To figure out if a principal can read a GCP bucket, Cartography:
1. Finds all policy bindings for that principal (including group memberships)
2. Checks if any bindings have the required permission
3. Verifies the binding scope matches the resource
4. Creates `(:GCPPrincipal)-[:CAN_READ]->(:GCPBucket)` if everything checks out

**Why this is hard without Cartography:** You'd manually check IAM bindings in the GCP Console for each resource, look up role permissions, verify scopes, handle group membership... and repeat for every bucket and every project. Alternatives like GCP Console/gcloud are resource-by-resource (not queryable), custom scripts require maintenance, and third-party tools are expensive without graph-based querying.

**Why Cartography wins:** One Cypher query gives you answers across resources, projects, and even cloud providers.

## How I Learned to Stop Worrying and Love the Graph

Following Cartography's established patterns, I implemented RPR for both Azure and GCP using the same general approach:

### 1. Parse Permission Relationship Files

Both Azure and GCP RPR use YAML configuration files (similar to AWS) that define which permission relationships should be created:

**Azure example:**
```yaml
- target_label: AzureSQLServer
  permissions:
  - Microsoft.Sql/servers/read
  relationship_name: CAN_READ
```

**GCP example:**
```yaml
- target_label: GCPBucket
  permissions:
  - storage.objects.get
  relationship_name: CAN_READ
```

### 2. Gather Principal and Resource Data

For each cloud provider, I implemented functions to:
- **Azure**: Query Neo4j for all EntraUser, EntraGroup, and EntraServicePrincipal nodes with their role assignments and permissions
- **GCP**: Query Neo4j for all GCPPrincipal nodes with their IAM policy bindings, roles, and permissions

### 3. Evaluate Permissions

The core logic evaluates whether a principal has the required permissions for a specific resource:

**Azure evaluation:**
- Check if the principal has a role assignment with the required permission
- Verify the role assignment scope matches the resource
- Handle group membership expansion (users are connected to groups in Neo4j, giving us the full picture, its pretty neat)

**GCP evaluation:**
- Check if the principal has a policy binding with the required permission
- Evaluate the binding scope (project, folder, or organization level)
- Verify allowed permissions match

### 4. Create Relationships

Once permissions are evaluated, Cartography creates MatchLink relationships in the graph:

- **Azure**: `(:EntraUser|EntraGroup|EntraServicePrincipal)-[:CAN_READ]->(:AzureSQLServer)`

image
- **GCP**: `(:GCPPrincipal)-[:CAN_READ]->(:GCPBucket)`

image

These relationships are created using Cartography's MatchLink system, which connects existing nodes in the graph based on permission evaluations.

## Technical Challenges (More Fun Than Expected)

### Azure Scope Matching: The Hierarchy Game

resource hierarchy image

Azure role assignments can be scoped at different levels:
- Subscription level (the whole thing)
- Resource group level (a subset)
- Individual resource level (just this one thing)

I had to implement scope resolution logic to figure out if a role assignment actually applies to a specific resource. This meant understanding Azure's resource hierarchy and checking if a resource falls under a given scope. It's like a game of "does this resource belong to this scope?" and the answer isn't always obvious.

### Performance Optimization: Making It Fast

Both implementations needed to be efficient because we're potentially processing thousands of principals and resources. Nobody wants to wait hours for a sync to finish. I optimized by:
- Pre-compiling permission patterns and scopes (compile once, use many times)
- Batching Neo4j queries where possible (fewer round trips = faster)
- Using efficient data structures for lookups
- Implementing proper cleanup jobs to remove stale relationships

The goal was to make it fast enough that people would actually use it. So far, so good!

## Example Queries: Putting RPR to Work (The Fun Part!)

Now for the good stuff! With Azure and GCP RPR implemented, security teams can ask all sorts of powerful questions across AWS, Azure, and GCP. Let's see what you can do:

### Find who can read sensitive Azure SQL Servers:

```cypher
MATCH (sql:AzureSQLServer{name:"sensitive-db"})<-[:CAN_READ]-(principal:EntraPrincipal)
RETURN principal.id, principal.name
```

The result shows all EntraUsers, EntraGroups, and EntraServicePrincipals that have been assigned roles containing the `Microsoft.Sql/servers/read` permission scoped to this SQL Server.

### Find who can write to GCP buckets:

```cypher
MATCH (bucket:GCPBucket{name:"sensitive-data"})<-[:CAN_WRITE]-(principal:GCPPrincipal)
RETURN principal.email, principal.type
```

This query returns all GCP principals (users, service accounts, or groups) that have IAM policy bindings with permissions like `storage.objects.create` or `storage.objects.update` for the specified bucket.

## My LFX Mentorship Experience (The Real Talk)

Working on Cartography through the LFX Mentorship program was honestly one of the best learning experiences I've had. I got to work closely with some amazing people:

- **Alex Chantavy** - My mentor, who patiently answered all my questions about Cartography's architecture, reviewed my code (and caught all my mistakes), and taught me best practices
- **Kunal Sikka** - Another mentor who helped me wrap my head around graph data modeling and Neo4j query optimization (turns out, there's a lot to learn!)

The mentorship taught me a ton:
- **Graph database design**: How to model complex permission relationships in Neo4j (it's not just nodes and edges, there's actual thought that goes into it!)
- **Open source collaboration**: Working with maintainers, handling code reviews (and learning to love feedback), and contributing to a real production codebase
- **Cloud security**: Deep understanding of how AWS, Azure, and GCP handle access control differently (spoiler: they're all different, and that's annoying but also interesting)
- **Software engineering**: Writing maintainable, testable code that follows established patterns (because nobody wants to maintain spaghetti code)

One of the coolest parts was realizing that the feature I built would actually be used by security teams to answer real questions about their cloud infrastructure. Like, actual people are going to use this to figure out who has access to what. That's pretty wild when you think about it!

The ability to query "who has access to what" across AWS, Azure, and GCP in a single graph database is honestly powerful for organizations operating in multi-cloud environments. No more jumping between three different consoles trying to piece together permissions. Just one query, and boom—you have your answer.

## Conclusion (That's a Wrap!)

We hope you found this post useful and maybe even a little bit fun! If you're curious, definitely check out the tool at [https://github.com/cartography-cncf/cartography](https://github.com/cartography-cncf/cartography).

Implementing Resource Permission Relationships for Azure and GCP was challenging but super rewarding. I learned a ton about cloud security, graph databases, and open source development. Big thanks to the Cartography maintainers, especially Alex Chantavy and Kunal Sikka, for being awesome mentors throughout the LFX Mentorship program. They put up with all my questions and helped me build something actually useful!

The problem of understanding IAM permissions across multiple cloud providers is perfect for a graph-based solution, and honestly, we're just getting started. The ability to query "who has access to what" across AWS, Azure, and GCP in a single graph database is pretty powerful for organizations operating in multi-cloud environments. No more context switching between three different consoles—just one query and you're done.

If you have questions or want to chat, come say hi in the Cartography community channels or at our monthly public community meetings. The open source security community is super welcoming and always looking for contributors. Whether you're into cloud security, graph databases, Python development, or just want to learn something new, there's a place for you in projects like Cartography.

Thanks for reading, and happy querying!
