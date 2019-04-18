/**
 * Copyright (c) 2015 Kaj Magnus Lindberg
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package debiki.dao

import com.debiki.core._
import com.debiki.core.Prelude._
import scala.collection.immutable
import ForumDao._
import talkyard.server.CommonMarkSourceAndHtml


case class CreateForumOptions(
  isForEmbeddedComments: Boolean,
  title: String,
  folder: String,
  useCategories: Boolean,
  createSupportCategory: Boolean,
  createIdeasCategory: Boolean,
  createSampleTopics: Boolean,
  topicListStyle: TopicListLayout)


case class CreateForumResult(
  pagePath: PagePathWithId,
  staffCategoryId: CategoryId,
  defaultCategoryId: CategoryId)


/** Creates forums.
  */
trait ForumDao {
  self: SiteDao =>


  def createForum(title: String, folder: String, isForEmbCmts: Boolean, byWho: Who)
        : Option[CreateForumResult] = {
    createForum(CreateForumOptions(
      isForEmbeddedComments = isForEmbCmts,
      title = title,
      folder = folder,
      useCategories = !isForEmbCmts,
      createSupportCategory = false,
      createIdeasCategory = false,
      createSampleTopics = !isForEmbCmts,
      topicListStyle = TopicListLayout.TitleExcerptSameLine), byWho)
  }


  def createForum(options: CreateForumOptions, byWho: Who): Option[CreateForumResult] = {
    val titleHtmlSanitized = context.nashorn.sanitizeHtml(options.title, followLinks = false)
    val isForEmbCmts = options.isForEmbeddedComments

    val result = readWriteTransaction { tx =>
      val oldForumPagePath = tx.checkPagePath(PagePath(
        siteId = siteId, folder = options.folder, pageId = None, showId = false, pageSlug = ""))
      if (oldForumPagePath.isDefined) {
        // There's already a page here; this is probably a create-forum double submit.
        // Can happen if  non-existing-page.more.ts  is open in two browser tabs
        // at the same time — maybe because the user pasted an email verification link
        // in a new 2nd tab. Do nothing.
        return None
      }

      // The forum page points to the root category, which points back.
      tx.deferConstraints()
      val creator = tx.loadTheUser(byWho.id)

      AuditDao.insertAuditLogEntry(AuditLogEntry(
        siteId,
        id = AuditLogEntry.UnassignedId,
        didWhat = AuditLogEntryType.CreateForum,
        doerId = byWho.id,
        doneAt = tx.now.toJavaDate,
        // Incl email, so will remember forever the created-by-email, even if the user
        // changes hens email later.
        emailAddress = creator.email.trimNoneIfEmpty,
        browserIdData = byWho.browserIdData,
        browserLocation = None), tx)

      val rootCategoryId = tx.nextCategoryId()

      // Create forum page.
      val introText = isForEmbCmts ? EmbeddedCommentsIntroText | ForumIntroText
      val forumPagePath = createPageImpl(
        PageType.Forum, PageStatus.Published, anyCategoryId = Some(rootCategoryId),
        anyFolder = Some(options.folder), anySlug = Some(""), showId = false,
        titleSource = options.title, titleHtmlSanitized = titleHtmlSanitized,
        bodySource = introText.source, bodyHtmlSanitized = introText.html,
        pinOrder = None, pinWhere = None,
        byWho, spamRelReqStuff = None, tx, layout = Some(options.topicListStyle))._1

      val forumPageId = forumPagePath.pageId

      val partialResult: CreateForumResult = createDefaultCategoriesAndTopics(
        forumPageId, rootCategoryId, options, byWho, tx)

      val settings =
        if (isForEmbCmts) {
          Some(SettingsToSave(
            showCategories = Some(Some(false)),
            showTopicFilterButton = Some(Some(false)),
            showTopicTypes = Some(Some(false)),
            selectTopicType = Some(Some(false))))
        }
        else if (!options.useCategories) {
          Some(SettingsToSave(
            showCategories = Some(Some(false))))
        }
        else None

      settings.foreach(tx.upsertSiteSettings)

      partialResult.copy(pagePath = forumPagePath)
    }

    // So settings get refreshed (might have been changed above.)
    emptyCache()

    Some(result)
  }


  private def createDefaultCategoriesAndTopics(forumPageId: PageId, rootCategoryId: CategoryId,
        options: CreateForumOptions, byWho: Who, tx: SiteTransaction)
        : CreateForumResult = {

    val staffCategoryId = rootCategoryId + 1
    val defaultCategoryId = rootCategoryId + 2
    val bySystem = Who(SystemUserId, byWho.browserIdData)

    // Create forum root category.
    tx.insertCategoryMarkSectionPageStale(Category(
      id = rootCategoryId,
      sectionPageId = forumPageId,
      parentId = None,
      defaultSubCatId = Some(defaultCategoryId),
      name = RootCategoryName,
      slug = RootCategorySlug,
      position = 1,
      description = None,
      newTopicTypes = Nil,
      unlistCategory = false,
      unlistTopics = false,
      includeInSummaries = IncludeInSummaries.Default,
      createdAt = tx.now.toJavaDate,
      updatedAt = tx.now.toJavaDate))

    // Create the Staff category.
    createCategoryImpl(
      CategoryToSave(
        anyId = Some(staffCategoryId),
        sectionPageId = forumPageId,
        parentId = rootCategoryId,
        shallBeDefaultCategory = false,
        name = "Staff",
        slug = "staff",
        position = DefaultCategoryPosition + 10,
        description = "Private category for staff discussions.",
        newTopicTypes = immutable.Seq(PageType.Discussion),
        unlistCategory = false,
        unlistTopics = false,
        includeInSummaries = IncludeInSummaries.Default),
      immutable.Seq[PermsOnPages](
        makeStaffCategoryPerms(staffCategoryId)),
      bySystem)(tx)

    if (options.isForEmbeddedComments)
      createEmbeddedCommentsCategory(forumPageId, rootCategoryId, defaultCategoryId,
        staffCategoryId, options, bySystem, tx)
    else
      createForumCategories(forumPageId, rootCategoryId, defaultCategoryId,
        staffCategoryId, options, bySystem, tx)
  }


  private def createEmbeddedCommentsCategory(
    forumPageId: PageId, rootCategoryId: CategoryId, defaultCategoryId: CategoryId,
    staffCategoryId: CategoryId, options: CreateForumOptions,
    bySystem: Who, tx: SiteTransaction): CreateForumResult = {

    dieIf(!options.isForEmbeddedComments, "TyE7HQT42")

    createCategoryImpl(
      CategoryToSave(
        anyId = Some(defaultCategoryId),
        sectionPageId = forumPageId,
        parentId = rootCategoryId,
        shallBeDefaultCategory = true,
        name = EmbCommentsCategoryName,
        slug = EmbCommentsCategorySlug,
        position = DefaultCategoryPosition,
        description = "Embedded comments for your blog or articles.",
        newTopicTypes = immutable.Seq(PageType.Discussion),
        // Strangers may not list all topics, maybe blog owner wants to keep some of them private?
        // SECURITY [rand-page-id]
        unlistCategory = true,
        unlistTopics = false,
        // The category About page is not needed, because the same info is in the forum
        // intro post anyway and there's only one single category. So create the About topic
        // in a deleted state, so it won't be shown. Can be undeleted later if one wants
        // a "real" forum with many categories.
        createDeletedAboutTopic = true,
        includeInSummaries = IncludeInSummaries.NoExclude),
      immutable.Seq[PermsOnPages](
        makeEveryonesDefaultCategoryPerms(defaultCategoryId),
        makeStaffCategoryPerms(defaultCategoryId)),
      bySystem)(tx)

    CreateForumResult(null, defaultCategoryId = defaultCategoryId,
      staffCategoryId = staffCategoryId)
  }


  private def createForumCategories(
    forumPageId: PageId, rootCategoryId: CategoryId, defaultCategoryId: CategoryId,
    staffCategoryId: CategoryId, options: CreateForumOptions,
    bySystem: Who, tx: SiteTransaction): CreateForumResult = {

    dieIf(options.isForEmbeddedComments, "TyE2PKQ9")

    var nextCategoryId = defaultCategoryId
    def getAndBumpCategoryId() = {
      nextCategoryId += 1
      nextCategoryId - 1
    }

    //var anySupportCategoryId: Option[CategoryId] = None  [NODEFCATS]
    //var anyIdeasCategoryId: Option[CategoryId] = None
    var uncategorizedCategoryId: CategoryId = -1
    var anySampleTopicsCategoryId: Option[CategoryId] = None

    /*
    if (options.createSupportCategory) {  [NODEFCATS]
      val categoryId = getAndBumpCategoryId()
      anySupportCategoryId = Some(categoryId)
      createCategoryImpl(
        CategoryToSave(
          anyId = Some(categoryId),
          sectionPageId = forumPageId,
          parentId = rootCategoryId,
          shallBeDefaultCategory = categoryId == defaultCategoryId,
          name = "Support",
          slug = "support",
          position = DefaultCategoryPosition - 2,
          description = "Here you can ask questions and report problems.",
          newTopicTypes = immutable.Seq(PageType.Question),
          unlistCategory = false,
          unlistTopics = false,
          includeInSummaries = IncludeInSummaries.Default),
        immutable.Seq[PermsOnPages](
          makeEveryonesDefaultCategoryPerms(categoryId),
          makeStaffCategoryPerms(categoryId)),
        bySystem)(tx)
    }

    if (options.createIdeasCategory) {  [NODEFCATS]
      val categoryId = getAndBumpCategoryId()
      anyIdeasCategoryId = Some(categoryId)
      createCategoryImpl(
        CategoryToSave(
          anyId = Some(categoryId),
          sectionPageId = forumPageId,
          parentId = rootCategoryId,
          shallBeDefaultCategory = categoryId == defaultCategoryId,
          name = "Ideas",
          slug = "ideas",
          position = DefaultCategoryPosition - 1,
          description = "Here you can suggest new ideas.",
          newTopicTypes = immutable.Seq(PageType.Idea),
          unlistCategory = false,
          unlistTopics = false,
          includeInSummaries = IncludeInSummaries.Default),
        immutable.Seq[PermsOnPages](
          makeEveryonesDefaultCategoryPerms(categoryId),
          makeStaffCategoryPerms(categoryId)),
        bySystem)(tx)
    }
    */

    // Create the General category.
    uncategorizedCategoryId = getAndBumpCategoryId()
    createCategoryImpl(
        CategoryToSave(
          anyId = Some(uncategorizedCategoryId),
          sectionPageId = forumPageId,
          parentId = rootCategoryId,
          shallBeDefaultCategory = uncategorizedCategoryId == defaultCategoryId,
          name = UncategorizedCategoryName,
          slug = UncategorizedCategorySlug,
          position = DefaultCategoryPosition,
          description = "For topics that don't fit in other categories.",
          newTopicTypes = immutable.Seq(PageType.Question),
          unlistCategory = false,
          unlistTopics = false,
          includeInSummaries = IncludeInSummaries.Default),
        immutable.Seq[PermsOnPages](
          makeEveryonesDefaultCategoryPerms(uncategorizedCategoryId),
          makeStaffCategoryPerms(uncategorizedCategoryId)),
        bySystem)(tx)

    if (options.createSampleTopics) {
      val categoryId = getAndBumpCategoryId()
      anySampleTopicsCategoryId = Some(categoryId)
      createCategoryImpl(
        CategoryToSave(
          anyId = Some(categoryId),
          sectionPageId = forumPageId,
          parentId = rootCategoryId,
          shallBeDefaultCategory = false,
          name = "Sample Topics",
          slug = "sample-topics",
          position = DefaultCategoryPosition + 100,
          description =
            o"""Sample topics of different types, okay to delete.""",
            // yes now they are [4AKBR02]: They aren't listed in the main
              //topic list — you'll see them only if you open this sample topics category.""",
          newTopicTypes = immutable.Seq(PageType.Discussion),
          unlistCategory = false,
          unlistTopics = false,  // so won't appear in the main topic list
                                 // edit: Now I just hid all category-descr topics. [4AKBR02]
                                 // Let's try again, with showing the sample topics by default.
          includeInSummaries = IncludeInSummaries.NoExclude),
        immutable.Seq[PermsOnPages](
          makeEveryonesDefaultCategoryPerms(categoryId),
          makeStaffCategoryPerms(categoryId)),
        bySystem)(tx)
    }

    // Create forum welcome topic.
    createPageImpl(
      PageType.Discussion, PageStatus.Published,
      anyCategoryId = Some(uncategorizedCategoryId),
      anyFolder = None, anySlug = Some("welcome"), showId = true,
      titleSource = WelcomeTopicTitle,
      titleHtmlSanitized = WelcomeTopicTitle,
      bodySource = welcomeTopic.source,
      bodyHtmlSanitized = welcomeTopic.html,
      pinOrder = Some(WelcomeToForumTopicPinOrder),
      pinWhere = Some(PinPageWhere.Globally),
      bySystem,
      spamRelReqStuff = None,
      tx)

    if (options.createSampleTopics) {
      def wrap(text: String) = textAndHtmlMaker.wrapInParagraphNoMentionsOrLinks(text, isTitle = false)

      // Create a sample open-ended discussion.
      val discussionPagePath = createPageImpl(
        PageType.Discussion, PageStatus.Published,
        anyCategoryId = anySampleTopicsCategoryId,
        anyFolder = None, anySlug = Some("sample-discussion"), showId = true,
        titleSource = SampleThreadedDiscussionTitle,
        titleHtmlSanitized = SampleThreadedDiscussionTitle,
        bodySource = SampleThreadedDiscussionText,
        bodyHtmlSanitized = s"<p>$SampleThreadedDiscussionText</p>",
        pinOrder = None,
        pinWhere = None,
        bySystem,
        spamRelReqStuff = None,
        tx)._1
      // ... with a brief discussion.
      insertReplyImpl(wrap(SampleDiscussionReplyOne),
        discussionPagePath.pageId, replyToPostNrs = Set(PageParts.BodyNr), PostType.Normal,
        bySystem, SystemSpamStuff, globals.now(), SystemUserId, tx, skipNotifications = true)
      insertReplyImpl(wrap(SampleDiscussionReplyTwo),
        discussionPagePath.pageId, replyToPostNrs = Set(PageParts.FirstReplyNr), PostType.Normal,
        bySystem, SystemSpamStuff, globals.now(), SystemUserId, tx, skipNotifications = true)
      insertReplyImpl(wrap(SampleDiscussionReplyThree),
        discussionPagePath.pageId, replyToPostNrs = Set(PageParts.FirstReplyNr + 1), PostType.Normal,
        bySystem, SystemSpamStuff, globals.now(), SystemUserId, tx, skipNotifications = true)

      /*
      // Create sample problem. — maybe it's enough, with a sample Idea.
      createPageImpl(
        PageType.Problem, PageStatus.Published,
        anyCategoryId = anySampleTopicsCategoryId,
        anyFolder = None, anySlug = Some("sample-problem"), showId = true,
        titleSource = SampleProblemTitle,
        titleHtmlSanitized = SampleProblemTitle,
        bodySource = SampleProblemText.source,
        bodyHtmlSanitized = SampleProblemText.html,
        pinOrder = None,
        pinWhere = None,
        bySystem,
        spamRelReqStuff = None,
        tx) */

      // Create sample idea.
      val ideaPagePath = createPageImpl(
        PageType.Idea, PageStatus.Published,
        anyCategoryId = anySampleTopicsCategoryId,
        anyFolder = None, anySlug = Some("sample-idea"), showId = true,
        titleSource = SampleIdeaTitle,
        titleHtmlSanitized = SampleIdeaTitle,
        bodySource = SampleIdeaText.source,
        bodyHtmlSanitized = SampleIdeaText.html,
        pinOrder = None,
        pinWhere = None,
        bySystem,
        spamRelReqStuff = None,
        tx)._1
      // ... with some sample Discussion and Progress replies.
      insertReplyImpl(wrap(SampleIdeaDiscussionReplyOne),
        ideaPagePath.pageId, replyToPostNrs = Set(PageParts.BodyNr), PostType.Normal,
        bySystem, SystemSpamStuff, globals.now(), SystemUserId, tx, skipNotifications = true)
      insertReplyImpl(wrap(SampleIdeaDiscussionReplyTwo),
        ideaPagePath.pageId, replyToPostNrs = Set(PageParts.FirstReplyNr), PostType.Normal,
        bySystem, SystemSpamStuff, globals.now(), SystemUserId, tx, skipNotifications = true)
      insertReplyImpl(wrap(SampleIdeaDiscussionReplyThree),
        ideaPagePath.pageId, replyToPostNrs = Set(PageParts.FirstReplyNr + 1), PostType.Normal,
        bySystem, SystemSpamStuff, globals.now(), SystemUserId, tx, skipNotifications = true)
      insertReplyImpl(wrap(SampleIdeaProgressReplyOne),
        ideaPagePath.pageId, replyToPostNrs = Set(PageParts.BodyNr), PostType.BottomComment,
        bySystem, SystemSpamStuff, globals.now(), SystemUserId, tx, skipNotifications = true)
      insertReplyImpl(wrap(SampleIdeaProgressReplyTwo),
        ideaPagePath.pageId, replyToPostNrs = Set(PageParts.BodyNr), PostType.BottomComment,
        bySystem, SystemSpamStuff, globals.now(), SystemUserId, tx, skipNotifications = true)

      // Create sample question.
      val questionPagePath = createPageImpl(
        PageType.Question, PageStatus.Published,
        anyCategoryId = anySampleTopicsCategoryId,
        anyFolder = None, anySlug = Some("sample-question"), showId = true,
        titleSource = SampleQuestionTitle,
        titleHtmlSanitized = SampleQuestionTitle,
        bodySource = SampleQuestionText.source,
        bodyHtmlSanitized = SampleQuestionText.html,
        pinOrder = None,
        pinWhere = None,
        bySystem,
        spamRelReqStuff = None,
        tx)._1
      // ... with two answers and a comment:
      insertReplyImpl(wrap(SampleAnswerText),
        questionPagePath.pageId, replyToPostNrs = Set(PageParts.BodyNr), PostType.Normal,
        bySystem, SystemSpamStuff, globals.now(), SystemUserId, tx, skipNotifications = true)
      insertReplyImpl(wrap(SampleAnswerCommentText),
        questionPagePath.pageId, replyToPostNrs = Set(PageParts.FirstReplyNr), PostType.Normal,
        bySystem, SystemSpamStuff, globals.now(), SystemUserId, tx, skipNotifications = true)
      insertReplyImpl(wrap(SampleAnswerText2),
        questionPagePath.pageId, replyToPostNrs = Set(PageParts.BodyNr), PostType.Normal,
        bySystem, SystemSpamStuff, globals.now(), SystemUserId, tx, skipNotifications = true)
    }

    // Create staff chat.
    // (Create after the sample topics above, so will appear above them in the
    // topic list, because is newer.)
    createPageImpl(
      PageType.OpenChat, PageStatus.Published,
      anyCategoryId = Some(staffCategoryId),
      anyFolder = None, anySlug = Some("staff-chat"), showId = true,
      titleSource = StaffChatTopicTitle,
      titleHtmlSanitized = StaffChatTopicTitle,
      bodySource = StaffChatTopicText,
      bodyHtmlSanitized = s"<p>$StaffChatTopicText</p>",
      pinOrder = None,
      pinWhere = None,
      bySystem,
      spamRelReqStuff = None,
      tx)

    CreateForumResult(null, defaultCategoryId = defaultCategoryId,
      staffCategoryId = staffCategoryId)
  }

}


object ForumDao {

  private val WelcomeToForumTopicPinOrder = 5

  private val RootCategoryName = "(Root Category)"  // In Typescript test code too [7UKPX5]
  private val RootCategorySlug = "(root-category)"  //

  private val UncategorizedCategoryName = "General" // I18N everywhere here
  private val UncategorizedCategorySlug = "general"

  private val EmbCommentsCategoryName = "Blog Comments"
  private val EmbCommentsCategorySlug = "blog-comments"

  private val DefaultCategoryPosition = 1000


  private val ForumIntroText: CommonMarkSourceAndHtml = {
    val source = o"""[ Edit this to tell people what they can do here. ]"""
    CommonMarkSourceAndHtml(source, html = s"<p>$source</p>")
  }


  private val EmbeddedCommentsIntroText: CommonMarkSourceAndHtml = {
    val source = o"""Here are comments posted at your website. One topic here,
         for each blog post that got any comments, over at your website."""
    CommonMarkSourceAndHtml(source, html = s"<p>$source</p>")
  }


  private val WelcomeTopicTitle = "Welcome to this community"

  private val welcomeTopic: CommonMarkSourceAndHtml = {
    val para1Line1 = "[ Edit this to clarify what this community is about. This first paragraph"
    val para1Line2 = "is shown to everyone, on the forum homepage. ]"
    val para2Line1 = "Here, below the first paragraph, add details like:"
    val listItem1 = "Who is this community for?"
    val listItem2 = "What can they do or find here?"
    val listItem3 = "Link to additional info, for example, any FAQ, or main website of yours."
    val toEditText = """To edit this, click the <b class="icon-edit"></b> icon below."""
    CommonMarkSourceAndHtml(
      source = i"""
        |$para1Line1
        |$para1Line2
        |
        |$para2Line1
        |- $listItem1
        |- $listItem2
        |- $listItem3
        |
        |$toEditText
        |""",
      html = i"""
        |<p>$para1Line1 $para1Line2</p>
        |<p>$para2Line1</p>
        |<ol><li>$listItem1</li><li>$listItem2</li><li>$listItem3</li></ol>
        |<p>$toEditText</p>
        """)
  }

  private val ToDeleteText =
    "(To delete this example topic, click Tools at the top, and then click Delete.)"

  private val StaffChatTopicTitle = "Staff chat"
  private val StaffChatTopicText = "This is a private chat for staff."


  private val SampleThreadedDiscussionTitle = "Sample discussion"
  private val SampleThreadedDiscussionText =
    o"""This is an open ended discussion. Good comments rise to the top, and people can click
       Disagree to show that they disagree about something."""

  private val SampleDiscussionReplyOne = o"""Lorem ipsum dolor sit amet, consectetur adipiscing elit,
      sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam,
      quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat."""
  private val SampleDiscussionReplyTwo = SampleDiscussionReplyOne.takeWhile(_ != '.')
  private val SampleDiscussionReplyThree = SampleDiscussionReplyTwo


  private val SampleProblemTitle = "Sample problem"
  private val SampleProblemText = {
    val para1 = o"""If you get a report about something being broken, and you need to fix it,
      you can change the topic type to Problem (like this topic) — click the pencil to the
      right of the title."""
    val para2 =
      o"""Then, when you decide to fix the problem,
      click <span class="icon-attention-circled"></span> to the left of the title,
      to change the status to We-plan-to-fix-this.
      Click again to change status to Fixing-now, and Fixed."""
    val para3 = o"""In the topic list, people see if a problem is new, or if it's been solved:
      the <span class="icon-attention-circled"></span> and
      <span class="icon-check"></span> icons."""
    CommonMarkSourceAndHtml(
      source = i"""
        |$para1
        |
        |$para2
        |
        |$para3
        |
        |$ToDeleteText
        |""",
      html = i"""
        |<p>$para1</p>
        |<p>$para2</p>
        |<p>$para3</p>
        |<p>$ToDeleteText</p>
        """)
  }


  private val SampleIdeaTitle = "Sample idea"
  private val SampleIdeaText = {
    val para1 = o"""This is a sample idea. Click the idea icon to the left of the title
      (i.e. <span class="icon-idea"></span>)
      to change status from New Idea, to Planned-to-do, to Doing-now, to Done."""
    val para2 = o"""In the topic list, everyone sees the status of the idea at a glance
      — the status icon is shown to the left (e.g.
      <span class="icon-idea"></span> or <span class="icon-check"></span>).</div>"""
    CommonMarkSourceAndHtml(
      source = i"""
        |$para1
        |
        |$para2
        |
        |$ToDeleteText
        |""",
      html = i"""
        |<p>$para1</p>
        |<p>$para2</p>
        |<p>$ToDeleteText</p>
        """)
  }

  private val SampleIdeaDiscussionReplyOne = o"""Sample reply, discussing if the idea
     is a good idea."""

  private val SampleIdeaDiscussionReplyTwo = o"""
     More thoughts about the idea."""

  private val SampleIdeaDiscussionReplyThree = o"""
     These Discussion section replies are always threaded.
     Whilst the Progress section replies below, are flat."""

  private val SampleIdeaProgressReplyOne = o"""
     Here, in the Progress section,
     you can step by step update others,
     about how you're making progress with actually implementing the idea."""

  private val SampleIdeaProgressReplyTwo = o"""Now we have: ...,
     and next we will: ... (just some sample text, this)."""


  private val SampleQuestionTitle = "Sample question"
  private val SampleQuestionText = {
    val para1 = o"""This is an sample question. Click "Solution" below to accept an answer.
      In the topic list, everyone sees that this is a question, and if it's new
      (the <span class="icon-help-circled"></span> icon), or if it's been answered (
      the <span class="icon-ok-circled-empty"></span> icon)."""
    val para2 = o"""In the topic list: To see all unanswered questions, click "All topic"
      and then choose "Only waiting", look:"""
    // (You'll find /-/media/ in the Nginx config [NGXMEDIA] and submodule ty-media.)
    val para3 = """<img class="no-lightbox" src="/-/media/tips/how-click-show-waiting-680px.jpg">"""
    CommonMarkSourceAndHtml(
      source = i"""
        |$para1
        |
        |$para2
        |
        |$para3
        |
        |$ToDeleteText
        |""",
      html = i"""
        |<p>$para1</p>
        |<p>$para2</p>
        |$para3
        |<p>$ToDeleteText</p>
        """)
  }

  private val SampleAnswerText = o"""Sample answer. The one who posted the question,
    and the staff (you?), can click Solution below, to accept this answer and mark
    the question as solved."""

  private val SampleAnswerCommentText = o"""Here, someone has posted a comment, to start
    discussing the sample answers just above."""

  private val SampleAnswerText2 = o"""Another sample answer. Lorem ipsum dolor sit amet,
    consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
    Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex
    ea commodo consequat"""

  // SHOULD separate layout: chat/flat/threaded/2d, from
  // topic type: idea/question/discussion/wiki/etc ?
  //
  //val SampleFlatDiscussionTopicTitle = "Sample discussion, flat"
  //val SampleFlatDiscussionTopicText =
  // "If you prefer flat (not threaded) discussions, instead of threaded discussions,
  // you can edit the category and change the default topic type from Discussion to Chat."

  // Sync with dupl code in Typescript. [7KFWY025]
  def makeEveryonesDefaultCategoryPerms(categoryId: CategoryId) = PermsOnPages(
    id = NoPermissionId,
    forPeopleId = Group.EveryoneId,
    onCategoryId = Some(categoryId),
    mayEditOwn = Some(true),
    mayCreatePage = Some(true),
    mayPostComment = Some(true),
    maySee = Some(true),
    maySeeOwn = Some(true))


  // Sync with dupl code in Typescript. [7KFWY025]
  def makeStaffCategoryPerms(categoryId: CategoryId) = PermsOnPages(
    id = NoPermissionId,
    forPeopleId = Group.StaffId,
    onCategoryId = Some(categoryId),
    mayEditPage = Some(true),
    mayEditComment = Some(true),
    mayEditWiki = Some(true),
    mayEditOwn = Some(true),
    mayDeletePage = Some(true),
    mayDeleteComment = Some(true),
    mayCreatePage = Some(true),
    mayPostComment = Some(true),
    maySee = Some(true),
    maySeeOwn = Some(true))

}
