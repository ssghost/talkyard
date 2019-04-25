/// <reference path="../test-types.ts"/>

import * as _ from 'lodash';
import assert = require('assert');
import server = require('../utils/server');
import utils = require('../utils/utils');
import { buildSite } from '../utils/site-builder';
import pagesFor = require('../utils/pages-for');
import settings = require('../utils/settings');
import lad = require('../utils/log-and-die');
import c = require('../test-constants');

declare var browser: any;
declare var browserA: any;
declare var browserB: any;

let richBrowserA;
let richBrowserB;
let owen: Member;
let owensBrowser;
let maria: Member;
let mariasBrowser;

let siteIdAddress: IdAddress;
let siteId;

let forum: TwoPagesTestForum;

let discussionPageUrl: string;

const discPostOne = 'discPostOne';
const discPostOneReply = 'discPostOneReply';
const discPostOneReplyReply = 'discPostOneReplyReply';
const discPostOneReplyReplyReply = 'discPostOneReplyReplyReply';
const discPostOneReplyReplyReplyReply = 'discPostOneReplyReplyReplyReply';
const discPostOneReplyReplyReplyReplyReply = 'discPostOneReplyReplyReplyReplyReply';
const discPostTwo = 'discPostTwo';
const progrPostOne = 'progrPostOne';

const theReplyToMoveNr = c.FirstReplyNr + 3;
const otherOpDiscReplyNr = c.FirstReplyNr + 6;

describe("move posts  TyT03946HET3", () => {

  it("import a site", () => {
    const builder = buildSite();
    forum = builder.addTwoPagesForum({
      title: "Some E2E Test",
      members: undefined, // default = everyone
    });
    function addOnePost(nr: PostNr, parentNr: PostNr, text: string, postType?: PostType) {
      builder.addPost({
        page: forum.topics.byMichaelCategoryA,
        nr,
        parentNr,
        authorId: forum.members.michael.id,
        approvedSource: text,
        postType: postType,
      });
    }
    addOnePost(c.FirstReplyNr + 0, c.BodyNr, discPostOne);
    addOnePost(c.FirstReplyNr + 1, c.FirstReplyNr + 0, discPostOneReply);
    addOnePost(c.FirstReplyNr + 2, c.FirstReplyNr + 1, discPostOneReplyReply);

    assert.equal(c.FirstReplyNr + 3, theReplyToMoveNr);
    addOnePost(theReplyToMoveNr, c.FirstReplyNr + 2, discPostOneReplyReplyReply);

    addOnePost(c.FirstReplyNr + 4, c.FirstReplyNr + 3, discPostOneReplyReplyReplyReply);
    addOnePost(c.FirstReplyNr + 5, c.FirstReplyNr + 4, discPostOneReplyReplyReplyReplyReply);

    assert.equal(c.FirstReplyNr + 6, otherOpDiscReplyNr);
    addOnePost(otherOpDiscReplyNr, c.BodyNr, discPostTwo);

    addOnePost(c.FirstReplyNr + 7, c.BodyNr, progrPostOne, PostType.BottomComment);

    assert(builder.getSite() === forum.siteData);
    siteIdAddress = server.importSiteData(forum.siteData);
    siteId = siteIdAddress.id;
    discussionPageUrl = siteIdAddress.origin + '/' + forum.topics.byMichaelCategoryA.slug;
  });

  it("initialize people", () => {
    richBrowserA = _.assign(browserA, pagesFor(browserA));
    richBrowserB = _.assign(browserB, pagesFor(browserB));

    owen = forum.members.owen;
    owensBrowser = richBrowserA;
    maria = forum.members.maria;
    mariasBrowser = richBrowserB;
  });

  it("Owen logs in", () => {
    owensBrowser.go(siteIdAddress.origin + '/' + forum.topics.byMichaelCategoryA.slug);
    owensBrowser.complex.loginWithPasswordViaTopbar(owen);
    owensBrowser.disableRateLimits();
  });

  it("Sees the posts in the initial order", () => {
    owensBrowser.topic.forAllPostIndexNrElem((index, nr) => {
      // Originally, all post got so that their post nr is also their position from the top.
      assert.equal(nr, index);
    })
  });

  it("Copies the link to the 2nd OP discussion reply (the one without any replies)", () => {
    owensBrowser.topic.openShareDialogForPostNr(otherOpDiscReplyNr);
    owensBrowser.shareDialog.copyLinkToPost();
    owensBrowser.shareDialog.close();
  });

  it("Moves three replies to the other discussion OP reply: 1) Opens Move dialog", () => {
    owensBrowser.topic.openMoveDialogForPostNr(c.FirstReplyNr + 3);
  });

  it("... and 2) fills in destination, clicks Move", () => {
    owensBrowser.movePostDialog.pastePostLinkMoveToThere();
  });

  it("Now the replies appear below OP reply 2 (instead of above)", () => {
    owensBrowser.refresh(); // or sometimes this error:
    // "stale element reference: element is not attached to the page document"
    //  — React redraws the page in the middle of us checking all posts
    // below? and, in doing so, invalidating elem refs?
    verifyAfterFirstMoveOrder();
  });

  function verifyAfterFirstMoveOrder() {
    owensBrowser.topic.forAllPostIndexNrElem((index, nr) => {
      switch (index) {
        case 2:  assert.equal(nr, c.FirstReplyNr + 0);  break;
        case 3:  assert.equal(nr, c.FirstReplyNr + 1);  break;
        case 4:  assert.equal(nr, c.FirstReplyNr + 2);  break;
        case 5:  assert.equal(nr, c.FirstReplyNr + 6);  break; //          <———————.  ...this one
        case 6:  assert.equal(nr, c.FirstReplyNr + 3);  break; // These were...     |  = otherOpDiscReplyNr
        case 7:  assert.equal(nr, c.FirstReplyNr + 4);  break; // ...moved to       |
        case 8:  assert.equal(nr, c.FirstReplyNr + 5);  break; // ...children of ---`
        case 9:  assert.equal(nr, c.FirstReplyNr + 7);  break;
      }
    })
  }

  it("Moves the three first replies to the Progress section: 1) Opens Move dialog", () => {
    owensBrowser.topic.openMoveDialogForPostNr(c.FirstReplyNr + 0);
  });

  it("... and 2)  , clicks Move", () => {
    owensBrowser.movePostDialog.moveToOtherSection();
  });

  it("Now the first 3 replies are instead first in the Progress section", () => {
    owensBrowser.topic.forAllPostIndexNrElem((index, nr) => {
      switch (index) {
        case 2:  assert.equal(nr, c.FirstReplyNr + 6);  break;
        case 3:  assert.equal(nr, c.FirstReplyNr + 3);  break;
        case 4:  assert.equal(nr, c.FirstReplyNr + 4);  break;
        case 5:  assert.equal(nr, c.FirstReplyNr + 5);  break;
        case 6:  assert.equal(nr, c.FirstReplyNr + 0);  break; // <———.
        case 7:  assert.equal(nr, c.FirstReplyNr + 1);  break; // <————\——— were previously at the top
        case 8:  assert.equal(nr, c.FirstReplyNr + 2);  break; // <————/
        case 9:  assert.equal(nr, c.FirstReplyNr + 7);  break;
      }
    });
  });

  it("Owen moves them back: 1) Opens Move dialog", () => {
    owensBrowser.topic.openMoveDialogForPostNr(c.FirstReplyNr + 0);
  });

  it("... and 2) clicks Move To Other Section", () => {
    owensBrowser.movePostDialog.moveToOtherSection();
  });

  it("Now the firs replies appear first again", () => {
    verifyAfterFirstMoveOrder();
  });

});

