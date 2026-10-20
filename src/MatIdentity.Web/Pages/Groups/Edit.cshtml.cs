using System.ComponentModel.DataAnnotations;
using MatIdentity.Core.Access;
using MatIdentity.Core.Entities;
using MatIdentity.Core.Users;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MatIdentity.Web.Pages.Groups;

/// <summary>Creates or changes a group and who is in it.</summary>
public class EditModel : PageModel
{
    private readonly GroupService _groups;
    private readonly UserService _users;
    private readonly MatIdentity.Core.Activity.ActivityService _activity;

    public EditModel(GroupService groups, UserService users, MatIdentity.Core.Activity.ActivityService activity)
    {
        _activity = activity;
        _groups = groups;
        _users = users;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public bool IsEdit => Input.Id is > 0;

    public IReadOnlyList<User> People { get; private set; } = [];

    [TempData] public string? StatusMessage { get; set; }

    public class InputModel
    {
        public long? Id { get; set; }

        [Required(ErrorMessage = "Please enter a name.")]
        [StringLength(100)]
        public string Name { get; set; } = string.Empty;

        [StringLength(500)]
        public string? Description { get; set; }

        public List<long> MemberIds { get; set; } = [];
    }

    public async Task<IActionResult> OnGetAsync(long? id)
    {
        People = await _users.GetAllAsync(HttpContext.RequestAborted);
        if (id is > 0)
        {
            var group = await _groups.GetAsync(id.Value, HttpContext.RequestAborted);
            if (group is null)
            {
                return NotFound();
            }

            Input = new InputModel
            {
                Id = group.Id,
                Name = group.Name,
                Description = group.Description,
                MemberIds = await _groups.MemberIdsAsync(group.Id, HttpContext.RequestAborted),
            };
        }

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var ct = HttpContext.RequestAborted;
        People = await _users.GetAllAsync(ct);
        if (IsEdit && await _groups.GetAsync(Input.Id!.Value, ct) is null)
        {
            return NotFound();
        }

        if (!string.IsNullOrWhiteSpace(Input.Name) && await _groups.NameExistsAsync(Input.Name, Input.Id, ct))
        {
            ModelState.AddModelError("Input.Name", "A group with this name exists already.");
        }

        if (!ModelState.IsValid)
        {
            return Page();
        }

        var known = People.Select(p => p.Id).ToHashSet();
        var members = Input.MemberIds.Where(known.Contains).ToList();
        await _groups.SaveAsync(Input.Id, Input.Name, Input.Description, members, ct);
        await _activity.WriteAsync(ActivityKind.GroupSaved, username: User.GetUsername(), ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString(),
            detail: $"{Input.Name.Trim()} ({members.Count} {(members.Count == 1 ? "person" : "people")})", ct: ct);
        StatusMessage = IsEdit ? "Group saved." : "Group created.";
        return RedirectToPage("/Groups/Index");
    }
}
